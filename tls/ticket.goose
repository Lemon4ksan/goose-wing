// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8446 §4.6.1 Stateless Session Ticket Encryption Key (STEK) rotation
// and TLS 1.3 resumption session ticket cache.
namespace wing;

import std;
import core from "..";

struct Tls13CachedSessionTicket {
    in_use:       bool      = false,
    server_name:  u8[..256] = [],
    ticket:       u8[..256] = [],
    psk:          u8[..48]  = [],
    age_add:      u32       = 0,
    lifetime:     u32       = 0,
    cipher_suite: u16       = 0,
    issued_at_ms: i64       = 0,
}

var g_tls13_tickets: Tls13CachedSessionTicket[16] = [Tls13CachedSessionTicket { .. }; 16];

// ---- Stateless Session Ticket Encryption Key (STEK) Rotation (RFC 8446 §4.6.1) ----

const STEK_TICKET_PLAINTEXT_LEN: i64 = 63; // 1B psk_len + 48B psk + 2B suite + 8B issued_ms + 4B lifetime
const STEK_TICKET_WIRE_LEN:      i64 = 95; // 4B key_name + 12B iv + 63B ciphertext + 16B tag

struct TlsTicketStek {
    key_name:     u8[4]  = [0; 4],
    aead_key:     u8[32] = [0; 32],
    created_sec:  i64    = 0,
    lifetime_sec: u32    = 86400,
    active:       bool   = false,
}

struct TlsTicketKeyRing {
    keys:        TlsTicketStek[2] = [TlsTicketStek { .. }; 2],
    current_idx: u8               = 0,
}

// Seals a stateless TLS 1.3 session ticket using the active STEK slot in `ring` with AES-256-GCM.
// Wire format (95 bytes): key_name[4] || iv[12] || ciphertext[63] || tag[16], with AAD = key_name[4] || iv[12].
//
// Example:
//   ring.keys[0].active = true, psk.len = 32, cipher_suite = 0x1301, issued_at_ms = 1000
//   returns: true, out_ticket.len = 95
fn seal_stateless_tls13_ticket<B>(
    ring:         const TlsTicketKeyRing&,
    psk:          const u8[..48]&,
    cipher_suite: u16,
    issued_at_ms: i64,
    nonce_iv:     const u8[12]&,
    out_ticket:   B&,
) -> bool {
    out_ticket.clear();
    let idx = (ring.current_idx & 1) as i64;
    let stek = ring.keys[idx];
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
    pt.push(psk_len_u8);
    for i in 48 {
        if i < psk.len {
            pt.push(psk[i]);
        } else {
            pt.push(0);
        }
    }
    core::append_u16_be(pt, cipher_suite);
    core::append_u64_be(pt, issued_u64);
    core::append_u32_be(pt, stek.lifetime_sec);

    var aad: u8[..16] = [];
    aad.append(stek.key_name[..]);
    aad.append(nonce_iv[..]);

    var ct: u8[63] = [0; 63];
    let tag, _, ok_seal = core::aes256_gcm_seal(stek.aead_key, nonce_iv, pt[..], aad[..], ct[..]);
    core::secure_zeroize_slice(pt[..]);
    guard ok_seal else { return false; }

    out_ticket.append(aad[..]);
    out_ticket.append(ct[..]);
    out_ticket.append(tag[..]);
    return true;
}

fn select_matching_stek(ring: const TlsTicketKeyRing&, key_name: const u8[:]) -> TlsTicketStek, bool {
    var matched = TlsTicketStek { .. };
    var found = false;
    for i in 2 {
        let candidate = ring.keys[i];
        if candidate.active && core::ct_eq_bytes(candidate.key_name[..], key_name) {
            matched = candidate;
            found = true;
        }
    }
    return matched, found;
}

inline fn calc_ticket_lifetime_ms(lifetime: u32) -> i64 {
    let clamped = min(lifetime, rfc::MAX_TICKET_LIFETIME_SECS) as i64;
    return core::mul_sat_i64(clamped, 1000);
}

inline fn is_stateless_ticket_within_lifetime(issued_ms: i64, now_ms: i64, lifetime: u32) -> bool {
    guard issued_ms >= 0 && now_ms >= issued_ms && lifetime > 0 && lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else {
        return false;
    }
    let elapsed_ms = core::sub_sat_i64(now_ms, issued_ms);
    let max_age_ms = calc_ticket_lifetime_ms(lifetime);
    return elapsed_ms <= max_age_ms;
}

fn unpack_stateless_ticket_plaintext(
    pt:         const u8[:],
    raw_ticket: const u8[:],
    now_ms:     i64,
    out:        Tls13CachedSessionTicket&,
) -> bool {
    let cs = core::read_be_u16(pt, 49);
    let issued_u64 = core::read_be_u64(pt, 51);
    let issued_ms = (issued_u64 & 0x7FFFFFFFFFFFFFFF) as i64;
    let lifetime = core::read_be_u32(pt, 59);
    guard pt.len == STEK_TICKET_PLAINTEXT_LEN else { return false; }
    let psk_len = pt[0] as i64;
    guard (psk_len == 32 || psk_len == 48) &&
        rfc::is_supported_tls13_cipher_suite(cs) &&
        is_stateless_ticket_within_lifetime(issued_ms, now_ms, lifetime) else {
        return false;
    }
    out.in_use = true;
    out.psk.clear();
    if psk_len == 32 {
        out.psk.append(pt[1..33]);
    } else {
        out.psk.append(pt[1..49]);
    }
    out.cipher_suite = cs;
    out.issued_at_ms = issued_ms;
    out.lifetime = lifetime;
    return out.ticket.try_set(raw_ticket);
}

// Opens and authenticates a stateless TLS 1.3 session ticket across both active/previous STEK slots in `ring`.
// Enforces constant-time `key_name` matching, AES-256-GCM AAD authentication, and ticket lifetime expiration.
//
// Example:
//   raw_ticket = <95-byte STEK-sealed ticket>, now_ms = 2000
//   returns: ticket with in_use = true, cipher_suite = 0x1301, ok = true
fn open_stateless_tls13_ticket(
    ring:       const TlsTicketKeyRing&,
    raw_ticket: const u8[:],
    now_ms:     i64,
) -> Tls13CachedSessionTicket, bool {
    var out = Tls13CachedSessionTicket { .. };
    guard raw_ticket.len == STEK_TICKET_WIRE_LEN else { return out, false; }

    let stek, found = select_matching_stek(ring, raw_ticket[0..4]);
    guard found else { return out, false; }

    var iv:  u8[12] = [0; 12];
    var tag: u8[16] = [0; 16];
    core::ct_copy_bytes(iv[..], raw_ticket[4..16]);
    core::ct_copy_bytes(tag[..], raw_ticket[79..95]);

    var pt: u8[..63] = [];
    let ok_open = core::aes256_gcm_open(
        stek.aead_key,
        iv,
        raw_ticket[16..79],
        raw_ticket[0..16],
        tag,
        pt,
    );
    guard ok_open && unpack_stateless_ticket_plaintext(pt[..], raw_ticket, now_ms, out) else {
        core::secure_zeroize_slice(pt[..]);
        return out, false;
    }

    core::secure_zeroize_slice(pt[..]);
    return out, true;
}

// Stores a derived TLS 1.3 resumption PSK (32 or 48 bytes) and ticket identity for a server hostname.
fn store_tls13_session_ticket(
    server_name:  const u8[:],
    ticket:       const u8[:],
    psk:          const u8[:],
    age_add:      u32,
    lifetime:     u32,
    cipher_suite: u16 = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
) {
    guard server_name.len > 0 && server_name.len <= 255 else { return; }
    guard ticket.len > 0 && ticket.len <= 256 && lifetime > 0 else { return; }
    guard psk.len == 32 || psk.len == 48 else { return; }
    for i in 16 {
        if g_tls13_tickets[i].in_use && g_tls13_tickets[i].server_name[..] == server_name {
            let _ = g_tls13_tickets[i].ticket.try_set(ticket);
            let _ = g_tls13_tickets[i].psk.try_set(psk);
            g_tls13_tickets[i].age_add = age_add;
            g_tls13_tickets[i].lifetime = lifetime;
            g_tls13_tickets[i].cipher_suite = cipher_suite;
            return;
        }
    }
    for i in 16 {
        if !g_tls13_tickets[i].in_use {
            g_tls13_tickets[i].in_use = true;
            let _ = g_tls13_tickets[i].server_name.try_set(server_name);
            let _ = g_tls13_tickets[i].ticket.try_set(ticket);
            let _ = g_tls13_tickets[i].psk.try_set(psk);
            g_tls13_tickets[i].age_add = age_add;
            g_tls13_tickets[i].lifetime = lifetime;
            g_tls13_tickets[i].cipher_suite = cipher_suite;
            return;
        }
    }
    let _ = g_tls13_tickets[0].server_name.try_set(server_name);
    let _ = g_tls13_tickets[0].ticket.try_set(ticket);
    let _ = g_tls13_tickets[0].psk.try_set(psk);
    g_tls13_tickets[0].age_add = age_add;
    g_tls13_tickets[0].lifetime = lifetime;
    g_tls13_tickets[0].cipher_suite = cipher_suite;
}

// Looks up a cached TLS 1.3 session ticket by server hostname, returning the full PSK and cipher suite.
fn lookup_tls13_session_ticket_full(
    server_name:      const u8[:],
    out_ticket:       u8[..256]&,
    out_psk:          u8[..48]&,
    out_age_add:      u32&,
    out_cipher_suite: u16&,
) -> bool {
    guard server_name.len > 0 else { return false; }
    for i in 16 {
        if g_tls13_tickets[i].in_use && g_tls13_tickets[i].server_name[..] == server_name {
            guard out_ticket.try_set(g_tls13_tickets[i].ticket[..]) &&
                out_psk.try_set(g_tls13_tickets[i].psk[..]) else {
                return false;
            }
            out_age_add = g_tls13_tickets[i].age_add;
            out_cipher_suite = g_tls13_tickets[i].cipher_suite;
            return true;
        }
    }
    return false;
}

// Looks up a cached TLS 1.3 session ticket by server hostname (32-byte PSK view).
fn lookup_tls13_session_ticket(
    server_name: const u8[:],
    out_ticket:  u8[..256]&,
    out_psk:     u8[32]&,
    out_age_add: u32&,
) -> bool {
    guard server_name.len > 0 else { return false; }
    for i in 16 {
        if g_tls13_tickets[i].in_use && g_tls13_tickets[i].server_name[..] == server_name {
            guard g_tls13_tickets[i].psk.len >= 32 &&
                out_ticket.try_set(g_tls13_tickets[i].ticket[..]) else {
                return false;
            }
            core::ct_copy_bytes(out_psk[..], g_tls13_tickets[i].psk[0..32]);
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
            guard g_tls13_tickets[i].psk.len >= 32 else { return false; }
            core::ct_copy_bytes(out_psk[..], g_tls13_tickets[i].psk[0..32]);
            return true;
        }
    }
    return false;
}

// Clears all cached TLS 1.3 session tickets and wipes their PSKs.
fn clear_tls13_session_tickets() {
    for i in 16 {
        core::secure_zeroize_slice(g_tls13_tickets[i].psk[..]);
        g_tls13_tickets[i].psk.clear();
        g_tls13_tickets[i].ticket.clear();
        g_tls13_tickets[i].server_name.clear();
        g_tls13_tickets[i].in_use = false;
    }
}
