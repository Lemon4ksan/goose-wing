// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8446 §4.6.1 Stateless Session Ticket Encryption Key (STEK) rotation
// and TLS 1.3 resumption session ticket cache.
namespace tls;

import std;
import core;
import .types;
import .ticket_internal;

// ---- Stateless Session Ticket Encryption Key (STEK) Rotation (RFC 8446 §4.6.1) ----

// Seals a stateless TLS 1.3 session ticket using the active STEK slot in `ring` with AES-256-GCM.
// Wire format (95 bytes): key_name[4] || iv[12] || ciphertext[63] || tag[16], with AAD = key_name[4] || iv[12].
//
// Example:
//   ring.keys[0].active = true, psk.len = 32, cipher_suite = 0x1301, issued_at_ms = 1000
//   returns: true, out_ticket.len = 95
fn seal_stateless_ticket<B>(
    ring:         const TicketKeyRing&,
    psk:          const u8[..48]&,
    cipher_suite: u16,
    issued_at_ms: i64,
    nonce_iv:     const u8[12]&,
    out_ticket:   B&,
) -> bool {
    var committed = false;
    defer if !committed { out_ticket.clear(); };
    let idx = (ring.current_idx & 1) as i64;
    let stek .= ring.keys[idx];
    let psk_len_u8 = (psk.len & 0xFF) as u8;
    let issued_u64 = (issued_at_ms & 0x7FFFFFFFFFFFFFFF) as u64;
    let valid_stek = stek.active &&
        stek.lifetime_sec > 0 &&
        stek.lifetime_sec <= rfc::MAX_TICKET_LIFETIME_SECS;
    guard issued_at_ms >= 0 && valid_stek else {
        return false;
    }
    guard (psk.len == 32 || psk.len == 48) && rfc::is_supported_tls13_cipher_suite(cipher_suite) else {
        return false;
    }
    guard out_ticket.cap >= STEK_TICKET_WIRE_LEN else { return false; }

    var pt: u8[..63] = [];
    defer core::secure_zeroize_slice(pt[..]);
    pt.push(psk_len_u8);
    for i in 48 {
        if i < psk.len {
            pt.push(psk[i]);
        } else {
            pt.push(0);
        }
    }
    pt.append_u16_be(cipher_suite);
    pt.append_u64_be(issued_u64);
    pt.append_u32_be(stek.lifetime_sec);

    var aad: u8[..16] = [];
    aad.append(stek.key_name[..]);
    aad.append(nonce_iv[..]);

    var ct: u8[63] = [0; 63];
    let tag, _, ok_seal = core::aes256_gcm_seal(stek.aead_key, nonce_iv, pt[..], aad[..], ct[..]);
    guard ok_seal else { return false; }

    out_ticket.clear();
    out_ticket.append(aad[..]);
    out_ticket.append(ct[..]);
    out_ticket.append(tag[..]);
    committed = true;
    return true;
}

// Opens and authenticates a stateless TLS 1.3 session ticket across both active/previous STEK slots in `ring`.
// Enforces constant-time `key_name` matching, AES-256-GCM AAD authentication, and ticket lifetime expiration.
//
// Example:
//   raw_ticket = <95-byte STEK-sealed ticket>, now_ms = 2000
//   returns: ticket with in_use = true, cipher_suite = 0x1301, ok = true
fn open_stateless_ticket(
    ring:       const TicketKeyRing&,
    raw_ticket: const u8[:],
    now_ms:     i64,
) -> CachedSessionTicket, bool {
    var out = CachedSessionTicket { .. };
    guard raw_ticket.len == STEK_TICKET_WIRE_LEN else { return out, false; }

    var stek, found = tls_internal::select_matching_stek(ring, raw_ticket[0..4]);
    defer core::secure_zeroize_32(stek.aead_key);
    guard found else { return out, false; }

    var iv:  u8[12] = [0; 12];
    var tag: u8[16] = [0; 16];
    core::ct_copy_bytes(iv[..], raw_ticket[4..16]);
    core::ct_copy_bytes(tag[..], raw_ticket[79..95]);

    var pt: u8[..63] = [];
    defer core::secure_zeroize_slice(pt[..]);
    let ok_open = core::aes256_gcm_open(
        stek.aead_key,
        iv,
        raw_ticket[16..79],
        raw_ticket[0..16],
        tag,
        pt,
    );
    guard ok_open && tls_internal::unpack_stateless_ticket_plaintext(pt[..], raw_ticket, now_ms, out) else {
        core::secure_zeroize_slice(out.psk[..]);
        return CachedSessionTicket { .. }, false;
    }

    return out, true;
}

// Stores a derived TLS 1.3 resumption PSK (32 or 48 bytes) and ticket identity for a server hostname.
fn store_session_ticket(
    server_name:  const u8[:],
    ticket:       const u8[:],
    psk:          const u8[:],
    age_add:      u32,
    lifetime:     u32,
    cipher_suite: u16 = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    issued_at_ms: i64 = 0,
) {
    guard server_name.len > 0 && server_name.len <= 255 else { return; }
    guard ticket.len > 0 && ticket.len <= 1024 &&
        lifetime > 0 && lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else {
        return;
    }
    guard psk.len == 32 || psk.len == 48 else { return; }
    let stamp_ms = if issued_at_ms > 0 { issued_at_ms } else { core::unix_milli(core::now()) };
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_TICKET_CACHE);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_TICKET_CACHE);
    for &entry in tls_internal::g_tls13_tickets {
        if entry.in_use && entry.server_name[..] == server_name {
            tls_internal::populate_cached_ticket_slot(
                entry, server_name, ticket, psk, age_add, lifetime, cipher_suite, stamp_ms,
            );
            return;
        }
    }
    for &entry in tls_internal::g_tls13_tickets {
        if !entry.in_use {
            tls_internal::populate_cached_ticket_slot(
                entry, server_name, ticket, psk, age_add, lifetime, cipher_suite, stamp_ms,
            );
            return;
        }
    }
    tls_internal::populate_cached_ticket_slot(
        tls_internal::g_tls13_tickets[0], server_name, ticket, psk, age_add, lifetime, cipher_suite, stamp_ms,
    );
}

// Looks up a cached TLS 1.3 session ticket by server hostname, returning the full PSK and cipher suite.
fn lookup_session_ticket_full<B>(
    server_name:      const u8[:],
    out_ticket:       B&,
    out_psk:          u8[..48]&,
    out_age_add:      u32&,
    out_cipher_suite: u16&,
    now_ms:           i64 = 0,
) -> bool {
    var committed = false;
    defer if !committed {
        out_ticket.clear();
        core::secure_zeroize_slice(out_psk[..]);
        out_psk.clear();
        out_age_add = 0;
        out_cipher_suite = 0;
    };
    guard server_name.len > 0 else { return false; }
    let cur_ms = if now_ms > 0 { now_ms } else { core::unix_milli(core::now()) };
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_TICKET_CACHE);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_TICKET_CACHE);
    for &entry in tls_internal::g_tls13_tickets {
        if entry.in_use && entry.server_name[..] == server_name {
            guard tls_internal::is_cached_ticket_fresh(entry, cur_ms) &&
                out_ticket.try_set(entry.ticket[..]) &&
                out_psk.try_set(entry.psk[..]) else {
                continue;
            }
            out_age_add = entry.age_add;
            out_cipher_suite = entry.cipher_suite;
            committed = true;
            return true;
        }
    }
    return false;
}

// Looks up a cached TLS 1.3 session ticket by server hostname (32-byte PSK view).
fn lookup_session_ticket<B>(
    server_name: const u8[:],
    out_ticket:  B&,
    out_psk:     u8[32]&,
    out_age_add: u32&,
    now_ms:      i64 = 0,
) -> bool {
    var committed = false;
    defer if !committed {
        out_ticket.clear();
        core::secure_zeroize_32(out_psk);
        out_age_add = 0;
    };
    guard server_name.len > 0 else { return false; }
    let cur_ms = if now_ms > 0 { now_ms } else { core::unix_milli(core::now()) };
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_TICKET_CACHE);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_TICKET_CACHE);
    for &entry in tls_internal::g_tls13_tickets {
        if entry.in_use && entry.server_name[..] == server_name {
            guard tls_internal::is_cached_ticket_fresh(entry, cur_ms) &&
                entry.psk.len >= 32 &&
                out_ticket.try_set(entry.ticket[..]) else {
                continue;
            }
            core::ct_copy_bytes(out_psk[..], entry.psk[0..32]);
            out_age_add = entry.age_add;
            committed = true;
            return true;
        }
    }
    return false;
}

// Clears all cached TLS 1.3 session tickets and wipes their PSKs.
fn clear_session_tickets() {
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_TICKET_CACHE);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_TICKET_CACHE);
    for &entry in tls_internal::g_tls13_tickets {
        core::secure_zeroize_slice(entry.psk[..]);
        entry.psk.clear();
        entry.ticket.clear();
        entry.server_name.clear();
        entry.in_use = false;
    }
}
