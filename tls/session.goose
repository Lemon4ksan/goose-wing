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
import .x509;
import .post_quantum;
import .cert_compression;
import .ech;
import net.tcp;

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
    if hash_id == internal::HASH_SHA384 {
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
    resumed:            bool               = false,
    negotiated_alpn:    u8[..32]           = [],
    server_name:        u8[..256]          = [],
    san_hosts:          u8[..128][..8]     = [],
    rx_plain_buf:       u8[..16384]        = [],
    rx_plain_pos:       i64                = 0,
    key_update_tracker: KeyUpdateTracker   = KeyUpdateTracker { .. },
    ticket_cache:       SessionTicketCache = SessionTicketCache { .. },
}

var g_tls_cipher_slots: TlsCipherSlot[64] = [TlsCipherSlot { .. }; 64];

struct Tls13CachedSessionTicket {
    in_use:      bool      = false,
    server_name: u8[..256] = [],
    ticket:      u8[..256] = [],
    psk:         u8[32]    = [0; 32],
    age_add:     u32       = 0,
    lifetime:    u32       = 0,
}

var g_tls13_tickets: Tls13CachedSessionTicket[16] = [Tls13CachedSessionTicket { .. }; 16];

// Stores a derived TLS 1.3 resumption PSK and ticket identity for a server hostname.
fn store_tls13_session_ticket(
    server_name: const u8[:],
    ticket:      const u8[:],
    psk:         const u8[32]&,
    age_add:     u32,
    lifetime:    u32,
) {
    guard server_name.len > 0 && server_name.len <= 255 else { return; }
    guard ticket.len > 0 && ticket.len <= 256 && lifetime > 0 else { return; }
    for i in 16 {
        if g_tls13_tickets[i].in_use && g_tls13_tickets[i].server_name[..] == server_name {
            let _ = g_tls13_tickets[i].ticket.try_set(ticket);
            for j in 32 { g_tls13_tickets[i].psk[j] = psk[j]; }
            g_tls13_tickets[i].age_add = age_add;
            g_tls13_tickets[i].lifetime = lifetime;
            return;
        }
    }
    for i in 16 {
        if !g_tls13_tickets[i].in_use {
            g_tls13_tickets[i].in_use = true;
            let _ = g_tls13_tickets[i].server_name.try_set(server_name);
            let _ = g_tls13_tickets[i].ticket.try_set(ticket);
            for j in 32 { g_tls13_tickets[i].psk[j] = psk[j]; }
            g_tls13_tickets[i].age_add = age_add;
            g_tls13_tickets[i].lifetime = lifetime;
            return;
        }
    }
    let _ = g_tls13_tickets[0].server_name.try_set(server_name);
    let _ = g_tls13_tickets[0].ticket.try_set(ticket);
    for j in 32 { g_tls13_tickets[0].psk[j] = psk[j]; }
    g_tls13_tickets[0].age_add = age_add;
    g_tls13_tickets[0].lifetime = lifetime;
}

// Looks up a cached TLS 1.3 session ticket by server hostname.
fn lookup_tls13_session_ticket(
    server_name: const u8[:],
    out_ticket:  u8[..256]&,
    out_psk:     u8[32]&,
    out_age_add: u32&,
) -> bool {
    guard server_name.len > 0 else { return false; }
    for i in 16 {
        if g_tls13_tickets[i].in_use && g_tls13_tickets[i].server_name[..] == server_name {
            guard out_ticket.try_set(g_tls13_tickets[i].ticket[..]) else { return false; }
            for j in 32 { out_psk[j] = g_tls13_tickets[i].psk[j]; }
            out_age_add = g_tls13_tickets[i].age_add;
            return true;
        }
    }
    return false;
}

// Looks up a cached TLS 1.3 session ticket by opaque ticket identity bytes (for server resumption).
fn lookup_tls13_ticket_by_identity(
    ticket_id: const u8[:],
    out_psk:   u8[32]&,
) -> bool {
    guard ticket_id.len > 0 else { return false; }
    for i in 16 {
        if g_tls13_tickets[i].in_use && core::ct_eq_bytes(g_tls13_tickets[i].ticket[..], ticket_id) {
            for j in 32 { out_psk[j] = g_tls13_tickets[i].psk[j]; }
            return true;
        }
    }
    return false;
}

// Clears all cached TLS 1.3 session tickets and wipes their PSKs.
fn clear_tls13_session_tickets() {
    for i in 16 {
        core::secure_zeroize_32(g_tls13_tickets[i].psk);
        g_tls13_tickets[i].ticket.clear();
        g_tls13_tickets[i].server_name.clear();
        g_tls13_tickets[i].in_use = false;
    }
}

// Returns the ALPN protocol negotiated on a cipher slot (empty if none).
inline fn tls_session_alpn(slot_idx: u16) -> const u8[:] {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS && g_tls_cipher_slots[idx].in_use else { return ""; }
    return g_tls_cipher_slots[idx].negotiated_alpn[..];
}

// Returns true if the TLS 1.3 session was established via PSK resumption.
inline fn tls_session_is_resumed(slot_idx: u16) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS && g_tls_cipher_slots[idx].in_use else { return false; }
    return g_tls_cipher_slots[idx].resumed;
}

// Allocates an unused slot from the global static cipher slot pool.
fn alloc_tls_cipher_slot() -> u16 {
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
            g_tls_cipher_slots[i].resumed = false;
            g_tls_cipher_slots[i].negotiated_alpn.clear();
            g_tls_cipher_slots[i].server_name.clear();
            g_tls_cipher_slots[i].san_hosts.clear();
            g_tls_cipher_slots[i].rx_plain_buf.clear();
            g_tls_cipher_slots[i].rx_plain_pos = 0;
            g_tls_cipher_slots[i].key_update_tracker = KeyUpdateTracker { .. };
            g_tls_cipher_slots[i].ticket_cache = SessionTicketCache { .. };
            return i as u16;
        }
    }
    return 0xFFFF;
}

// Releases a cipher slot and securely wipes all cryptographic key material.
fn free_tls_cipher_slot(slot_idx: u16) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return; }
    core::secure_zeroize_32(g_tls_cipher_slots[idx].rx_key);
    core::secure_zeroize_32(g_tls_cipher_slots[idx].tx_key);
    core::secure_zeroize_slice(g_tls_cipher_slots[idx].rx_iv[..]);
    core::secure_zeroize_slice(g_tls_cipher_slots[idx].tx_iv[..]);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].rx_traffic_secret);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].tx_traffic_secret);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].exporter_secret);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].resumption_secret);
    g_tls_cipher_slots[idx].san_hosts.clear();
    g_tls_cipher_slots[idx].rx_plain_buf.clear();
    g_tls_cipher_slots[idx].rx_plain_pos = 0;
    g_tls_cipher_slots[idx].in_use = false;
}

// Extracts DNS SubjectAltName entries from a DER X.509 certificate into `g_tls_cipher_slots[slot_idx].san_hosts`.
fn tls_populate_slot_san_hosts_from_der(slot_idx: u16, cert_der: const u8[:]) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS && g_tls_cipher_slots[idx].in_use else { return false; }
    var leaf_cert = ParsedCert { .. };
    guard parse_x509_certificate(cert_der, leaf_cert) else { return false; }
    var sans: SanEntry[..16] = [];
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
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS && g_tls_cipher_slots[idx].in_use else { return; }
    for &san in g_tls_cipher_slots[idx].san_hosts {
        let _ = out_sans.try_push(copy(san));
    }
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

    guard payload.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    var ct_buf: u8[..16640] = [];
    guard payload.len + 22 <= ct_buf.cap else { return false; }
    while ct_buf.len < payload.len + 22 {
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
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS && g_tls_cipher_slots[idx].in_use else { return false; }

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
    guard tls_send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]) else { return false; }

    if ticket_lifetime > 0 && ticket.len > 0 && ticket.len <= 256 {
        var ks_res = internal::KeySchedule {
            hash_id:           g_tls_cipher_slots[idx].hash_id,
            hash_len:          g_tls_cipher_slots[idx].hash_len,
            stage:             internal::KS_STAGE_RESUMPTION,
            resumption_secret: g_tls_cipher_slots[idx].resumption_secret,
            ..
        };
        var psk: u8[32] = [0; 32];
        if internal::ks_derive_resumption_psk(ks_res, ticket_nonce, psk[..]) {
            let sni = if g_tls_cipher_slots[idx].server_name.len > 0 {
                g_tls_cipher_slots[idx].server_name[..]
            } else {
                "server"
            };
            store_tls13_session_ticket(sni, ticket, psk, 0, ticket_lifetime);
        }
    }
    return true;
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

fn tls_process_received_nst(idx: i64, msg_body: const u8[:]) {
    var nst = NewSessionTicketMsg { .. };
    guard parse_new_session_ticket(msg_body, nst) else { return; }
    cache_session_ticket(g_tls_cipher_slots[idx].ticket_cache, nst);
    guard g_tls_cipher_slots[idx].server_name.len > 0 && nst.ticket_lifetime > 0 else { return; }
    var ks_res = internal::KeySchedule {
        hash_id:           g_tls_cipher_slots[idx].hash_id,
        hash_len:          g_tls_cipher_slots[idx].hash_len,
        stage:             internal::KS_STAGE_RESUMPTION,
        resumption_secret: g_tls_cipher_slots[idx].resumption_secret,
        ..
    };
    var psk: u8[32] = [0; 32];
    if internal::ks_derive_resumption_psk(ks_res, nst.ticket_nonce[..], psk[..]) {
        store_tls13_session_ticket(
            g_tls_cipher_slots[idx].server_name[..],
            nst.ticket[..],
            psk,
            nst.ticket_age_add,
            nst.ticket_lifetime,
        );
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
            tls_process_received_nst(idx, msg_body);
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
fn tls_transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return -1; }
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
    current_record_plain: u8[..32768] = [],
    current_offset:       i64         = 0,
    seq_num:              u64         = 0,
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
    guard remaining_plain >= total_len else { return false; }
    guard m_len <= out_msg_body.cap else { return false; }
    msg_type = mt;
    out_msg_body.clear();
    out_msg_body.append(slice[4..total_len]);
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
            continue;
        }
        guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return false; }

        compact_handshake_reader(r);
        let base_len = r.current_record_plain.len;
        let needed_len = core::add_sat_i64(base_len, payload_len);
        guard needed_len <= r.current_record_plain.cap else { return false; }
        while r.current_record_plain.len < needed_len { r.current_record_plain.push(0); }
        let dec_len, inner_type, alert_dec, ok_dec = tls_record_decrypt_into(
            cipher_suite,
            key,
            iv,
            r.seq_num,
            hdr_buf[..],
            ct_payload[..payload_len],
            r.current_record_plain[base_len..],
        );
        guard ok_dec && inner_type == rfc::TLS_CONTENT_HANDSHAKE else { return false; }
        increment_record_seq_num(r.seq_num);

        let final_len = core::add_sat_i64(base_len, dec_len);
        while r.current_record_plain.len > final_len {
            r.current_record_plain.pop();
        }
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
    client_cert_der:      u8[..4096]       = [],
    client_priv_seed:     u8[32]           = [0; 32],
    enable_pq_hybrid:     bool             = false,
    ech_config_list:      u8[..512]        = [],
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
    let _, ok = parse_tls13_certificate_chain_and_ocsp(payload, out_certs);
    return ok;
}

fn extract_leaf_ocsp_extension(ext_bytes: const u8[:]) -> const u8[:], bool {
    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(ext_bytes, entries) else { return "", false; }
    let status_data, has_st = find_extension(entries, rfc::TLS_EXT_STATUS_REQUEST);
    guard has_st else { return "", true; }
    return unwrap_tls_ocsp_response(status_data);
}

// Parses raw Certificate message payload into DER certificate slices and optional leaf OCSP response (RFC 8446 §4.4.2).
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04, 'C', 'E', 'R', 'T', 0x00, 0x00]
//   returns: out_leaf_ocsp = "", ok = true, out_certs.len = 1
fn parse_tls13_certificate_chain_and_ocsp(
    payload:   const u8[:],
    out_certs: const u8[:][..8]&,
) -> const u8[:], bool {
    var out_leaf_ocsp = payload[..0];
    var c = core::cursor_from(payload);
    let _, ok_ctx = core::read_u8_prefixed(c);
    guard ok_ctx else { return "", false; }
    let list_bytes, ok_list = core::read_u24_prefixed(c);
    guard ok_list && c.buf.len == 0 else { return "", false; }

    out_certs.clear();
    var lc = core::cursor_from(list_bytes);
    while lc.buf.len > 0 {
        let cert_bytes, ok_cert = core::read_u24_prefixed(lc);
        guard ok_cert && cert_bytes.len > 0 else { return "", false; }
        let ext_bytes, ok_ext = core::read_u16_prefixed(lc);
        guard ok_ext else { return "", false; }
        if out_certs.len == 0 && ext_bytes.len > 0 {
            let ocsp_der, ok_ocsp = extract_leaf_ocsp_extension(ext_bytes);
            guard ok_ocsp else { return "", false; }
            out_leaf_ocsp = ocsp_der;
        }
        guard out_certs.try_push(cert_bytes) else { return "", false; }
    }
    return out_leaf_ocsp, out_certs.len > 0;
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
    core::append_u16_be(out, rfc::TLS_EXT_ALPN);
    core::append_u16_be(out, (proto_list.len + 2) as u16);
    core::append_u16_be(out, proto_list.len as u16);
    out.append(proto_list[..]);
}

// Computes a TLS 1.3 PSK binder tag over a truncated ClientHello handshake message (RFC 8446 §4.2.11.2).
fn compute_tls13_psk_binder(
    binder_key:   const u8[32]&,
    truncated_ch: const u8[:],
    out_binder:   u8[32]&,
) -> bool {
    var finished_key: u8[32] = [0; 32];
    guard internal::hkdf_expand_label(
        internal::HASH_SHA256,
        binder_key[..],
        "finished",
        [],
        32,
        finished_key[..],
    ) else { return false; }
    let ch_hash = core::sha256(truncated_ch);
    let mac = core::hmac_sha256(finished_key[..], ch_hash[..]);
    for i in 32 { out_binder[i] = mac[i]; }
    core::secure_zeroize_32(finished_key);
    return true;
}

// Serializes a TLS 1.3 ClientHello payload with standard extensions (RFC 8446 §4.1.2).
fn build_tls13_client_hello_payload<B>(
    random:      const u8[32]&,
    client_pub:  const u8[32]&,
    server_name: const u8[:],
    alpn:        const u8[:],
    out:         B&,
    psk_ticket:  const u8[:] = "",
    psk_age_add: u32         = 0,
    enable_pq:   bool        = false,
    pq_pub:      const u8[:] = "",
    ech_ext_raw: const u8[:] = "",
) {
    out.clear();
    core::append_u16_be(out, rfc::TLS_LEGACY_VERSION_1_2);
    out.append(random[..]);
    out.push(32);
    out.append(random[..]);

    core::append_u16_be(out, 6);
    core::append_u16_be(out, rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    core::append_u16_be(out, rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    core::append_u16_be(out, rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256);
    out.push(1);
    out.push(0);

    var ext_buf: u8[..4096] = [];
    core::append_u16_be(ext_buf, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    core::append_u16_be(ext_buf, 3);
    ext_buf.push(2);
    core::append_u16_be(ext_buf, rfc::TLS_VERSION_1_3);

    let groups: u16[4] = [
        rfc::GROUP_X25519_MLKEM768,
        rfc::GROUP_X25519,
        rfc::GROUP_SECP256R1,
        rfc::GROUP_SECP384R1,
    ];
    let group_start = if enable_pq { 0 } else { 1 };
    encode_supported_groups_extension(ext_buf, groups[group_start..]);

    core::append_u16_be(ext_buf, rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    core::append_u16_be(ext_buf, 12);
    core::append_u16_be(ext_buf, 10);
    core::append_u16_be(ext_buf, rfc::SIG_SCHEME_ED25519);
    core::append_u16_be(ext_buf, rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256);
    core::append_u16_be(ext_buf, rfc::SIG_SCHEME_ECDSA_SECP384R1_SHA384);
    core::append_u16_be(ext_buf, rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256);
    core::append_u16_be(ext_buf, rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384);

    let comp_algos: u16[3] = [
        rfc::CERT_COMPRESSION_BROTLI,
        rfc::CERT_COMPRESSION_ZSTD,
        rfc::CERT_COMPRESSION_ZLIB,
    ];
    encode_compress_certificate_extension(ext_buf, comp_algos[..]);

    var shares: u8[..1280] = [];
    if enable_pq && pq_pub.len == rfc::MLKEM768_PUBLIC_LEN {
        var pq_share = internal::PostQuantumKeyShare {
            group:         rfc::GROUP_X25519_MLKEM768,
            x25519_public: client_pub,
            ..
        };
        core::ct_copy_bytes(pq_share.mlkem768_public[..], pq_pub);
        internal::format_hybrid_key_share(pq_share, shares);
    }
    core::append_u16_be(shares, rfc::GROUP_X25519);
    core::append_u16_be(shares, 32);
    shares.append(client_pub[..]);
    encode_key_share_client_extension(ext_buf, shares[..]);

    if validate_sni_host_bytes(server_name) {
        core::append_u16_be(ext_buf, rfc::TLS_EXT_SERVER_NAME);
        let sni_len = (server_name.len + 3) as u16;
        core::append_u16_be(ext_buf, sni_len + 2);
        core::append_u16_be(ext_buf, sni_len);
        ext_buf.push(0);
        core::append_u16_be(ext_buf, server_name.len as u16);
        ext_buf.append(server_name);
    }

    if alpn.len > 0 && alpn.len <= 255 {
        encode_alpn_extension_from_csv(ext_buf, alpn);
    }

    if ech_ext_raw.len > 0 && ech_ext_raw.len <= 1024 {
        core::append_u16_be(ext_buf, rfc::EXT_ENCRYPTED_CLIENT_HELLO);
        core::append_u16_be(ext_buf, ech_ext_raw.len as u16);
        ext_buf.append(ech_ext_raw);
    }

    encode_psk_client_extensions(ext_buf, psk_ticket, psk_age_add);

    core::append_u16_be(out, ext_buf.len as u16);
    out.append(ext_buf[..]);
}

// Encodes psk_key_exchange_modes (RFC 8446 §4.2.9) and pre_shared_key (RFC 8446 §4.2.11) extensions.
fn encode_psk_client_extensions<B>(out: B&, psk_ticket: const u8[:], psk_age_add: u32) {
    guard psk_ticket.len > 0 && psk_ticket.len <= 256 else { return; }
    core::append_u16_be(out, rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    core::append_u16_be(out, 2);
    out.push(1);
    out.push(1);

    let id_entry_len = (2 + psk_ticket.len + 4) as u16;
    let binders_entry_len: u16 = 33;
    let psk_ext_len = 2 + id_entry_len + 2 + binders_entry_len;
    core::append_u16_be(out, rfc::TLS_EXT_PRE_SHARED_KEY);
    core::append_u16_be(out, psk_ext_len);
    core::append_u16_be(out, id_entry_len);
    core::append_u16_be(out, psk_ticket.len as u16);
    out.append(psk_ticket);
    core::append_u32_be(out, psk_age_add);
    core::append_u16_be(out, binders_entry_len);
    out.push(32);
    for i in 32 { out.push(0); }
}

// Sends a plaintext TLS record containing a handshake message (RFC 8446 §5.1).
fn send_plaintext_handshake_record(fd: i64, hs_msg: const u8[:]) -> bool {
    guard hs_msg.len > 0 && hs_msg.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    var rec_buf: u8[..16640] = [];
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
    out_payload: u8[..16384]&,
    timeout_ms:  u32 = 5000,
) -> bool {
    var raw_msg: u8[..16384] = [];
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

// Parses ServerHello wire payload, extracting negotiated cipher suite, ephemeral public key, and PSK selection.
//
// Example:
//   payload = [0x02, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x13, 0x01]
//   returns: true, out_cipher_suite = 0x1301, out_server_pub = [32 bytes]
fn parse_server_hello_fields(
    payload:          const u8[:],
    out_cipher_suite: u16&,
    out_server_pub:   u8[32]&,
    out_psk_resumed:  bool&,
) -> bool {
    var is_hrr = false;
    var srv_group: u16        = 0;
    var srv_share: u8[..2048] = [];
    let ok = parse_server_hello_or_hrr(
        payload, out_cipher_suite, is_hrr, srv_group, srv_share, out_psk_resumed,
    );
    guard ok && !is_hrr && srv_group == rfc::GROUP_X25519 && srv_share.len == 32 else { return false; }
    for i in 32 { out_server_pub[i] = srv_share[i]; }
    return true;
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
    out_is_hrr = false;
    out_psk_resumed = false;
    out_group = 0;
    out_server_share.clear();

    var c = core::cursor_from(payload);
    let hs_type, ok_t = core::read_u8(c);
    guard ok_t && hs_type == rfc::TLS_HS_SERVER_HELLO else { return false; }
    let body, ok_b = core::read_u24_prefixed(c);
    guard ok_b && c.buf.len == 0 else { return false; }

    var bc = core::cursor_from(body);
    let ver, ok_v = core::read_u16(bc);
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 else { return false; }
    let srv_rand, ok_r = core::read_bytes(bc, 32);
    guard ok_r else { return false; }
    var rand_arr: u8[32] = [0; 32];
    core::ct_copy_bytes(rand_arr[..], srv_rand);
    out_is_hrr = is_hello_retry_request(rand_arr);

    let _, ok_sid = core::read_u8_prefixed(bc);
    guard ok_sid else { return false; }

    let cs, ok_cs = core::read_u16(bc);
    guard ok_cs && rfc::is_supported_tls13_cipher_suite(cs) else { return false; }
    out_cipher_suite = cs;

    let comp, ok_cm = core::read_u8(bc);
    guard ok_cm && comp == 0 else { return false; }

    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(bc.buf, entries) else { return false; }

    let ver_data, has_ver = find_extension(entries, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    guard has_ver else { return false; }
    let negotiated_ver, ok_ver = parse_server_supported_versions(ver_data);
    guard ok_ver && negotiated_ver == rfc::TLS_VERSION_1_3 else { return false; }

    if !out_is_hrr {
        guard validate_server_random_downgrade(rand_arr, rfc::TLS_VERSION_1_3, true) else { return false; }
    }

    let ks_data, has_ks = find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_ks else { return false; }
    if out_is_hrr {
        guard ks_data.len == 2 else { return false; }
        out_group = core::read_be_u16(ks_data, 0);
        return true;
    }

    guard parse_key_share_server_extension(ks_data, out_group, out_server_share) else { return false; }

    let psk_data, has_psk = find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk {
        guard psk_data.len == 2 else { return false; }
        let selected_idx = core::read_be_u16(psk_data, 0);
        guard selected_idx == 0 else { return false; }
        out_psk_resumed = true;
    }
    return true;
}

// Parses server EncryptedExtensions payload and extracts single negotiated ALPN protocol if present (RFC 7301 §3.1).
//
// Example:
//   ee_body = [0x00, 0x09, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2']
//   returns: true, out_alpn = "h2"
fn parse_encrypted_extensions_alpn(ee_body: const u8[:], out_alpn: u8[..32]&) -> bool {
    out_alpn.clear();
    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(ee_body, entries) else { return false; }
    let alpn_data, has_alpn = find_extension(entries, rfc::TLS_EXT_ALPN);
    guard has_alpn else { return true; }

    var ac = core::cursor_from(alpn_data);
    let list_bytes, ok_l = core::read_u16_prefixed(ac);
    guard ok_l && ac.buf.len == 0 && list_bytes.len >= 2 else { return false; }

    var lc = core::cursor_from(list_bytes);
    let proto, ok_p = core::read_u8_prefixed(lc);
    guard ok_p && lc.buf.len == 0 && proto.len >= 1 && proto.len <= 32 else { return false; }
    return out_alpn.try_set(proto);
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

        if leaf_ocsp.len > 0 {
            let ocsp_alert = validate_ocsp_stapling(leaf_ocsp, leaf_cert, chain_slices[0], eff_clock);
            guard ocsp_alert == TlsAlert.CloseNotify else { return false; }
        }

        if config.server_name.len > 0 {
            var sans: SanEntry[..16] = [];
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
fn tls_client_process_server_flight(
    hs_reader:             HandshakeRecordReader&,
    fd:                    i64,
    cipher_suite:          u16,
    server_hs_key:         const u8[:],
    server_hs_iv:          const u8[12]&,
    ks:                    const internal::KeySchedule&,
    transcript:            TlsTranscript&,
    config:                const TlsClientHandshakeConfig&,
    psk_resumed:           bool,
    out_alpn:              u8[..32]&,
    out_cert_req_received: bool&,
    slot_idx:              u16 = 0xFFFF,
) -> bool {
    out_cert_req_received = false;
    var msg_ee:  u8          = 0;
    var ee_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_ee, ee_body, 5000,
    ) else { return false; }
    guard msg_ee == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else { return false; }
    guard parse_encrypted_extensions_alpn(ee_body[..], out_alpn) else { return false; }
    transcript_update_msg(transcript, msg_ee, ee_body[..]);

    if !psk_resumed {
        var msg_next:  u8          = 0;
        var next_body: u8[..16384] = [];
        guard next_handshake_message(
            hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_next, next_body, 5000,
        ) else { return false; }

        if msg_next == rfc::TLS_HS_CERTIFICATE_REQUEST {
            var cert_req = CertificateRequestMsg { .. };
            guard parse_certificate_request(next_body[..], false, cert_req) else { return false; }
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
            guard decompress_incoming_certificate(next_body[..], decomp_cert) else { return false; }
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
    guard msg_fin == rfc::TLS_HS_FINISHED && fin_body.len == hlen else { return false; }

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    guard internal::ks_compute_finished_verify_data(
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
    guard hs_msg.len + 32 <= ct_buf.cap else { return false; }
    while ct_buf.len < hs_msg.len + 32 { ct_buf.push(0); }
    let s_len, _, ok_seal = tls_record_seal_into(
        cipher_suite, key, iv, seq,
        rfc::TLS_CONTENT_HANDSHAKE, hs_msg, ct_buf[..],
    );
    guard ok_seal && tls_write_all(fd, ct_buf[..s_len]) else { return false; }
    return true;
}

fn tls_client_send_client_cert(
    fd:            i64,
    cipher_suite:  u16,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    client_seq:    u64&,
    ks:            const internal::KeySchedule&,
    transcript:    TlsTranscript&,
    config:        const TlsClientHandshakeConfig&,
) -> bool {
    var cert_payload: u8[..4096] = [];
    guard encode_client_certificate(cert_payload, "", config.client_cert_der[..]) else { return false; }
    var cert_msg: u8[..4096] = [];
    cert_msg.push(rfc::TLS_HS_CERTIFICATE);
    core::append_u24_be(cert_msg, cert_payload.len as u32);
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
        let sig = core::ed25519_sign(config.client_priv_seed, cv_msg_buf[..cv_len]);

        var cv_payload: u8[..512] = [];
        guard encode_client_certificate_verify(cv_payload, rfc::SIG_SCHEME_ED25519, sig[..]) else { return false; }
        var cv_msg: u8[..512] = [];
        cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
        core::append_u24_be(cv_msg, cv_payload.len as u32);
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
    ks:                const internal::KeySchedule&,
    transcript:        TlsTranscript&,
    config:            const TlsClientHandshakeConfig&,
    cert_req_received: bool,
) -> bool {
    var client_seq: u64 = 0;
    if cert_req_received {
        guard tls_client_send_client_cert(
            fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, ks, transcript, config,
        ) else { return false; }
    }

    var h_through_prev: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_prev);
    var cli_fin_data: u8[48] = [0; 48];
    let hlen = ks.hash_len as i64;
    guard internal::ks_compute_finished_verify_data(
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
    ks:           const internal::KeySchedule&,
    c_ap_key:     const u8[:],
    c_ap_iv:      const u8[12]&,
    s_ap_key:     const u8[:],
    s_ap_iv:      const u8[12]&,
    server_name:  const u8[:],
    neg_alpn:     const u8[:],
    psk_resumed:  bool,
) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return; }
    let _ = g_tls_cipher_slots[idx].server_name.try_set(server_name);
    let _ = g_tls_cipher_slots[idx].negotiated_alpn.try_set(neg_alpn);
    g_tls_cipher_slots[idx].resumed = psk_resumed;
    g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    g_tls_cipher_slots[idx].key_len = key_len_u16;
    g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    g_tls_cipher_slots[idx].is_server = false;
    for i in c_ap_key.len { g_tls_cipher_slots[idx].tx_key[i] = c_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].tx_iv[i] = c_ap_iv[i]; }
    g_tls_cipher_slots[idx].tx_seq = 0;
    for i in s_ap_key.len { g_tls_cipher_slots[idx].rx_key[i] = s_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].rx_iv[i] = s_ap_iv[i]; }
    g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}

fn patch_client_hello_psk_binder<B>(ch_msg: B&, psk_secret: const u8[32]&) {
    guard ch_msg.len > 35 else { return; }
    var ks_early, ok_kse = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    guard ok_kse && internal::ks_init_early_secret(ks_early, psk_secret[..]) else { return; }
    var b_key: u8[32] = [0; 32];
    for i in 32 { b_key[i] = ks_early.binder_key[i]; }
    let trunc_ch, ok_tr = internal::truncate_client_hello_for_binder(ch_msg[..], 33);
    var binder: u8[32] = [0; 32];
    guard ok_tr && compute_tls13_psk_binder(b_key, trunc_ch, binder) else { return; }
    while ch_msg.len > trunc_ch.len { ch_msg.pop(); }
    core::append_u16_be(ch_msg, 33);
    ch_msg.push(32);
    ch_msg.append(binder[..]);
}

fn prepare_ech_outer_extension(ech_config_list: const u8[:], out: u8[..512]&) {
    guard ech_config_list.len > 0 else { return; }
    var ech_list = EchConfigList { .. };
    guard parse_ech_config_list(ech_config_list, ech_list) else { return; }
    var ech_cfg = EchConfig { .. };
    var ech_cs = EchCipherSuite { .. };
    guard select_ech_config(ech_list, ech_cfg, ech_cs) else { return; }
    let ech_enc = tls_random_bytes_32();
    var ech_ct: u8[..128] = [];
    while ech_ct.len < 32 { ech_ct.push(0); }
    build_ech_outer_extension(ech_cfg.config_id, ech_cs, ech_enc, ech_ct[..], out);
}

// Executes full TLS 1.3 client handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn tls_client_handshake(fd: i64, config: const TlsClientHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_tls_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }

    let client_random = tls_random_bytes_32();
    let client_priv = tls_random_bytes_32();
    let client_pub = core::x25519_base_scalarmult(client_priv);

    var pq_priv: u8[2400] = [0; 2400];
    var pq_pub:  u8[1152] = [0; 1152];
    if config.enable_pq_hybrid {
        let pq_seed = tls_random_bytes_32();
        core::ct_copy_bytes(pq_priv[0..32], pq_seed[..]);
        core::ct_copy_bytes(pq_pub[0..32], pq_seed[..]);
    }

    var psk_ticket:  u8[..256] = [];
    var psk_secret:  u8[32]    = [0; 32];
    var psk_age_add: u32       = 0;
    let has_ticket = lookup_tls13_session_ticket(
        config.server_name[..], psk_ticket, psk_secret, psk_age_add,
    );

    var ech_ext_raw: u8[..512] = [];
    prepare_ech_outer_extension(config.ech_config_list[..], ech_ext_raw);

    var ch_payload: u8[..4096] = [];
    build_tls13_client_hello_payload(
        client_random, client_pub, config.server_name[..], config.alpn[..],
        ch_payload, psk_ticket[..], psk_age_add,
        config.enable_pq_hybrid, if config.enable_pq_hybrid { pq_pub[..] } else { "" },
        ech_ext_raw[..],
    );
    var ch_msg: u8[..4096] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_msg, ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    if has_ticket {
        patch_client_hello_psk_binder(ch_msg, psk_secret);
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

    var cipher_suite: u16        = 0;
    var is_hrr:       bool       = false;
    var srv_group:    u16        = 0;
    var srv_share:    u8[..2048] = [];
    var psk_resumed:  bool       = false;
    guard parse_server_hello_or_hrr(
        sh_msg[..], cipher_suite, is_hrr, srv_group, srv_share, psk_resumed,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    if is_hrr {
        transcript_update(transcript, sh_msg[..]);
        var ks_hrr, ok_kshr = internal::ks_init(cipher_suite);
        guard ok_kshr && transcript_replace_with_message_hash(transcript, ks_hrr.hash_id, ks_hrr.hash_len) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }

        var ch2_payload: u8[..4096] = [];
        build_tls13_client_hello_payload(
            client_random, client_pub, config.server_name[..], config.alpn[..],
            ch2_payload, "", 0,
            config.enable_pq_hybrid, if config.enable_pq_hybrid { pq_pub[..] } else { "" },
            ech_ext_raw[..],
        );
        var ch2_msg: u8[..4096] = [];
        ch2_msg.push(rfc::TLS_HS_CLIENT_HELLO);
        core::append_u24_be(ch2_msg, ch2_payload.len as u32);
        ch2_msg.append(ch2_payload[..]);

        guard send_plaintext_handshake_record(fd, ch2_msg[..]) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        transcript_update(transcript, ch2_msg[..]);

        sh_msg.clear();
        guard read_plaintext_handshake_record(fd, sh_msg) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        guard parse_server_hello_or_hrr(
            sh_msg[..], cipher_suite, is_hrr, srv_group, srv_share, psk_resumed,
        ) && !is_hrr else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    }

    transcript_update(transcript, sh_msg[..]);

    if psk_resumed && !has_ticket {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ecdhe_secret: u8[32] = [0; 32];
    if srv_group == rfc::GROUP_X25519_MLKEM768 {
        var srv_share_raw: u8[..2048] = [];
        core::append_u16_be(srv_share_raw, srv_group);
        core::append_u16_be(srv_share_raw, srv_share.len as u16);
        srv_share_raw.append(srv_share[..]);
        var srv_pq_share = internal::PostQuantumServerShare { .. };
        guard internal::parse_hybrid_server_key_share(srv_pq_share, srv_share_raw[..]) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        let classic_ss, ok_c = core::x25519_shared_secret(client_priv, srv_pq_share.x25519_public);
        guard ok_c else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        var pq_ss: u8[32] = [0; 32];
        guard internal::mlkem768_decapsulate(srv_pq_share.mlkem768_ciphertext[..], pq_priv[..], pq_ss[..]) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        guard internal::derive_x25519_mlkem768_shared_secret_checked(classic_ss[..], pq_ss[..], ecdhe_secret[..]) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else if srv_group == rfc::GROUP_X25519 && srv_share.len == 32 {
        var srv_pub: u8[32] = [0; 32];
        core::ct_copy_bytes(srv_pub[..], srv_share[..]);
        let ss, ok_ss = core::x25519_shared_secret(client_priv, srv_pub);
        guard ok_ss else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        core::ct_copy_bytes(ecdhe_secret[..], ss[..]);
    } else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ks, ok_ks = internal::ks_init(cipher_suite);
    let early_ikm = if psk_resumed { psk_secret[..] } else { "" };
    let ok_ks_adv = ok_ks &&
        internal::ks_init_early_secret(ks, early_ikm) &&
        internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var client_hs_key: u8[32] = [0; 32];
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    var server_hs_iv:  u8[12] = [0; 12];
    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
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
    var neg_alpn: u8[..32] = [];
    var cert_req_received = false;
    let ok_flight = tls_client_process_server_flight(
        hs_reader, fd, cipher_suite, server_hs_key[..klen],
        server_hs_iv, ks, transcript, config, psk_resumed, neg_alpn,
        cert_req_received, slot_idx,
    );
    guard ok_flight else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    guard tls_client_send_finished(
        fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript,
        config, cert_req_received,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_cli_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_cli_fin);
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

    tls_setup_client_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        client_ap_key[..klen], client_ap_iv,
        server_ap_key[..klen], server_ap_iv,
        config.server_name[..], neg_alpn[..], psk_resumed,
    );
    return slot_idx, true;
}

// Matches a client ALPN extension against server comma-separated ALPN preferences (RFC 7301 §3.2).
fn select_server_alpn_from_ext(
    alpn_ext:        const u8[:],
    server_alpn_csv: const u8[:],
    out_alpn:        u8[..32]&,
) -> bool {
    out_alpn.clear();
    guard alpn_ext.len >= 3 else { return false; }
    guard server_alpn_csv.len > 0 else { return true; }
    var c = core::cursor_from(alpn_ext);
    let list_bytes, ok_l = core::read_u16_prefixed(c);
    guard ok_l && c.buf.len == 0 && list_bytes.len >= 1 else { return false; }

    var sc: i64 = 0;
    while sc < server_alpn_csv.len {
        var comma = sc;
        while comma < server_alpn_csv.len && server_alpn_csv[comma] != ',' { comma++; }
        let srv_proto = server_alpn_csv[sc..comma];
        sc = comma + 1;
        if srv_proto.len == 0 || srv_proto.len > 32 { continue; }
        var lc = core::cursor_from(list_bytes);
        while lc.buf.len > 0 {
            let cli_proto, ok_p = core::read_u8_prefixed(lc);
            guard ok_p && cli_proto.len > 0 else { return false; }
            if cli_proto == srv_proto { return out_alpn.try_set(srv_proto); }
        }
    }
    return true;
}

// Verifies ClientHello pre_shared_key extension and PSK binder against cached server tickets (RFC 8446 §4.2.11).
fn verify_client_hello_psk_binder(
    ch_msg:  const u8[:],
    psk_ext: const u8[:],
    out_psk: u8[32]&,
) -> bool {
    var c = core::cursor_from(psk_ext);
    let ids_bytes, ok_ids = core::read_u16_prefixed(c);
    guard ok_ids && ids_bytes.len >= 7 else { return false; }
    let binders_bytes, ok_b = core::read_u16_prefixed(c);
    guard ok_b && c.buf.len == 0 && binders_bytes.len == 33 else { return false; }

    var ic = core::cursor_from(ids_bytes);
    let ticket_id, ok_t = core::read_u16_prefixed(ic);
    guard ok_t && ticket_id.len > 0 else { return false; }
    let _, ok_age = core::read_u32(ic);
    guard ok_age else { return false; }

    var bc = core::cursor_from(binders_bytes);
    let binder_slice, ok_bs = core::read_u8_prefixed(bc);
    guard ok_bs && binder_slice.len == 32 && bc.buf.len == 0 else { return false; }

    guard lookup_tls13_ticket_by_identity(ticket_id, out_psk) else { return false; }

    var ks_early, ok_kse = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    guard ok_kse && internal::ks_init_early_secret(ks_early, out_psk[..]) else { return false; }

    var b_key: u8[32] = [0; 32];
    for i in 32 { b_key[i] = ks_early.binder_key[i]; }
    let trunc_ch, ok_tr = internal::truncate_client_hello_for_binder(ch_msg, 33);
    guard ok_tr else { return false; }
    var exp_binder: u8[32] = [0; 32];
    guard compute_tls13_psk_binder(b_key, trunc_ch, exp_binder) else { return false; }
    return core::ct_eq_bytes(exp_binder[..], binder_slice);
}

fn verify_client_hello_psk_entry(
    entries: const TlsExtensionEntry[..32]&,
    payload: const u8[:],
    psk_ext: const u8[:],
    out_psk: u8[32]&,
) -> bool {
    guard entries.len > 0 else { return false; }
    var last_type: u16 = 0;
    for e in entries { last_type = e.ext_type; }
    guard last_type == rfc::TLS_EXT_PRE_SHARED_KEY else { return false; }
    guard verify_client_hello_psk_binder(payload, psk_ext, out_psk) else {
        core::secure_zeroize_32(out_psk);
        return false;
    }
    return true;
}

// Extracts the 32-byte X25519 key share from a parsed KeyShareEntry list.
//
// Example:
//   shares = [0x00, 0x1D, 0x00, 0x20, ...32 bytes...]
//   returns: true, out_client_pub = [32 bytes]
fn extract_x25519_client_share(shares: const u8[:], out_client_pub: u8[32]&) -> bool {
    var sc = core::cursor_from(shares);
    while sc.buf.len > 0 {
        let group, ok_g = core::read_u16(sc);
        guard ok_g else { return false; }
        let kex_bytes, ok_k = core::read_u16_prefixed(sc);
        guard ok_k else { return false; }
        if group == rfc::GROUP_X25519 && kex_bytes.len == 32 {
            for i in 32 { out_client_pub[i] = kex_bytes[i]; }
            return true;
        }
    }
    return false;
}

// Parses ClientHello payload for server handshake, extracting session ID, client X25519 key share, ALPN, SNI, and PSK.
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
    out_alpn.clear();
    out_sni.clear();
    out_psk_resumed = false;
    var c = core::cursor_from(payload);
    let hs_type, ok_t = core::read_u8(c);
    guard ok_t && hs_type == rfc::TLS_HS_CLIENT_HELLO else { return false; }
    let body, ok_b = core::read_u24_prefixed(c);
    guard ok_b && c.buf.len == 0 else { return false; }

    var bc = core::cursor_from(body);
    let ver, ok_v = core::read_u16(bc);
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 else { return false; }
    let _, ok_r = core::read_bytes(bc, 32);
    guard ok_r else { return false; }

    let sid, ok_sid = core::read_u8_prefixed(bc);
    guard ok_sid && sid.len <= 32 else { return false; }
    let cs_bytes, ok_cs = core::read_u16_prefixed(bc);
    guard ok_cs && cs_bytes.len >= 2 else { return false; }
    let comp_bytes, ok_cm = core::read_u8_prefixed(bc);
    guard ok_cm && comp_bytes.len >= 1 else { return false; }

    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(bc.buf, entries) else { return false; }

    let sni_ext, has_sni = find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    if has_sni {
        guard parse_sni_extension(sni_ext, out_sni) else { return false; }
    }

    let ks_data, has_ks = find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_ks else { return false; }
    var shares: u8[..4096] = [];
    guard parse_key_share_client_extension(ks_data, shares) &&
        extract_x25519_client_share(shares[..], out_client_pub) else { return false; }

    let alpn_ext, has_alpn = find_extension(entries, rfc::TLS_EXT_ALPN);
    if has_alpn {
        guard select_server_alpn_from_ext(alpn_ext, server_alpn_csv, out_alpn) else { return false; }
    }

    let psk_ext, has_psk = find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk {
        guard verify_client_hello_psk_entry(entries, payload, psk_ext, out_psk_secret) else { return false; }
        out_psk_resumed = true;
    }
    return out_session_id.try_set(sid);
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
    server_random: const u8[32]&,
    session_id:    const u8[:],
    server_pub:    const u8[32]&,
    out:           B&,
    psk_resumed:   bool = false,
) {
    out.clear();
    core::append_u16_be(out, rfc::TLS_LEGACY_VERSION_1_2);
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
    if psk_resumed {
        core::append_u16_be(ext_buf, rfc::TLS_EXT_PRE_SHARED_KEY);
        core::append_u16_be(ext_buf, 2);
        core::append_u16_be(ext_buf, 0);
    }
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
    transcript:    TlsTranscript&,
) -> bool {
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(transcript, internal::HASH_SHA256, h_to_cert);
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
    var ee_ext: u8[..128] = [];
    if negotiated_alpn.len > 0 {
        encode_alpn_extension_from_csv(ee_ext, negotiated_alpn);
    }
    var ee_msg: u8[..160] = [];
    ee_msg.push(rfc::TLS_HS_ENCRYPTED_EXTENSIONS);
    core::append_u24_be(ee_msg, (2 + ee_ext.len) as u32);
    core::append_u16_be(ee_msg, ee_ext.len as u16);
    ee_msg.append(ee_ext[..]);
    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, ee_msg[..]) else {
        return false;
    }
    server_seq++;
    transcript_update(transcript, ee_msg[..]);
    return true;
}

// Encrypts and transmits the server handshake flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
fn tls_server_send_flight(
    fd:              i64,
    server_hs_key:   const u8[:],
    server_hs_iv:    const u8[12]&,
    ks:              const internal::KeySchedule&,
    transcript:      TlsTranscript&,
    config:          const TlsServerHandshakeConfig&,
    negotiated_alpn: const u8[:],
    psk_resumed:     bool,
) -> bool {
    let cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    var server_seq: u64 = 0;

    guard tls_server_send_ee(
        fd, cipher_suite, server_hs_key, server_hs_iv,
        server_seq, negotiated_alpn, transcript,
    ) else { return false; }

    if !psk_resumed {
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
        transcript_update(transcript, cert_msg[..]);

        guard tls_server_send_cv(
            fd, cipher_suite, server_hs_key, server_hs_iv,
            server_seq, config.priv_seed, transcript,
        ) else {
            return false;
        }
    }

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var srv_fin_data: u8[48] = [0; 48];
    let hlen = ks.hash_len as i64;
    let ok_fin_calc = internal::ks_compute_finished_verify_data(
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
    for i in s_ap_key.len { g_tls_cipher_slots[idx].tx_key[i] = s_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].tx_iv[i] = s_ap_iv[i]; }
    g_tls_cipher_slots[idx].tx_seq = 0;
    for i in c_ap_key.len { g_tls_cipher_slots[idx].rx_key[i] = c_ap_key[i]; }
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

    var session_id:  u8[..32]  = [];
    var client_pub:  u8[32]    = [0; 32];
    var neg_alpn:    u8[..32]  = [];
    var client_sni:  u8[..255] = [];
    var psk_resumed: bool      = false;
    var psk_secret:  u8[32]    = [0; 32];
    guard parse_client_hello_for_server_sni(
        ch_msg, config.alpn[..], session_id, client_pub,
        neg_alpn, client_sni, psk_resumed, psk_secret,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let _ = g_tls_cipher_slots[idx].server_name.try_set(client_sni[..]);

    let server_random = tls_random_bytes_32();
    let server_priv = tls_random_bytes_32();
    let server_pub = core::x25519_base_scalarmult(server_priv);

    let ecdhe_secret, ok_ecdhe = core::x25519_shared_secret(server_priv, client_pub);
    guard ok_ecdhe else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh_payload: u8[..2048] = [];
    build_tls13_server_hello_payload(server_random, session_id[..], server_pub, sh_payload, psk_resumed);
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
    transcript_update(transcript, sh_msg[..]);

    let cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    var ks, ok_ks = internal::ks_init(cipher_suite);
    let early_ikm = if psk_resumed { psk_secret[..] } else { "" };
    let ok_ks_adv = ok_ks &&
        internal::ks_init_early_secret(ks, early_ikm) &&
        internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
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

    guard tls_server_send_flight(
        fd, server_hs_key[..klen], server_hs_iv, ks,
        transcript, config, neg_alpn[..], psk_resumed,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
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
    guard msg_fin == rfc::TLS_HS_FINISHED && cli_fin_body.len == hlen else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var exp_cli_fin: u8[48] = [0; 48];
    let ok_exp_fin = internal::ks_compute_finished_verify_data(
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
