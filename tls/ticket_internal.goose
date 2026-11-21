// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal STEK selection, plaintext unpacking, and session ticket cache storage (RFC 8446 §4.6.1).
namespace tls_internal;

import std;
import core from "..";
import .internal;
import .types;

var g_tls13_tickets: tls::CachedSessionTicket[16] = [tls::CachedSessionTicket { .. }; 16];

fn select_matching_stek(ring: const tls::TicketKeyRing&, key_name: const u8[:]) -> tls::TicketStek, bool {
    var matched = tls::TicketStek { .. };
    var found = false;
    for i in 2 {
        let candidate .= ring.keys[i];
        if candidate.active && core::ct_eq_bytes(candidate.key_name[..], key_name) {
            matched = candidate;
            found = true;
        }
    }
    return matched, found;
}

fn unpack_stateless_ticket_plaintext(
    pt:         const u8[:],
    raw_ticket: const u8[:],
    now_ms:     i64,
    out:        tls::CachedSessionTicket&,
) -> bool {
    guard pt.len == tls::STEK_TICKET_PLAINTEXT_LEN else { return false; }
    let cs = core::read_be_u16(pt, 49);
    let issued_u64 = core::read_be_u64(pt, 51);
    let issued_ms = (issued_u64 & 0x7FFFFFFFFFFFFFFF) as i64;
    let lifetime = core::read_be_u32(pt, 59);
    let psk_len = pt[0] as i64;
    guard (psk_len == 32 || psk_len == 48) &&
        rfc::is_supported_tls13_cipher_suite(cs) &&
        is_stateless_ticket_within_lifetime(issued_ms, now_ms, lifetime) else {
        return false;
    }
    let psk_slice = if psk_len == 32 { pt[1..33] } else { pt[1..49] };
    guard out.psk.try_set(psk_slice) && out.ticket.try_set(raw_ticket) else { return false; }
    out.in_use = true;
    out.cipher_suite = cs;
    out.issued_at_ms = issued_ms;
    out.lifetime = lifetime;
    return true;
}

inline fn is_cached_ticket_fresh(entry: const tls::CachedSessionTicket&, now_ms: i64) -> bool {
    guard entry.lifetime > 0 && entry.lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else { return false; }
    guard entry.issued_at_ms > 0 && now_ms > 0 else { return false; }
    return is_stateless_ticket_within_lifetime(entry.issued_at_ms, now_ms, entry.lifetime);
}

inline fn populate_cached_ticket_slot(
    slot:         tls::CachedSessionTicket&,
    server_name:  const u8[:],
    ticket:       const u8[:],
    psk:          const u8[:],
    age_add:      u32,
    lifetime:     u32,
    cipher_suite: u16,
    stamp_ms:     i64,
) {
    core::secure_zeroize_slice(slot.psk[..]);
    slot.in_use = true;
    let _ = slot.server_name.try_set(server_name);
    let _ = slot.ticket.try_set(ticket);
    let _ = slot.psk.try_set(psk);
    slot.age_add = age_add;
    slot.lifetime = lifetime;
    slot.cipher_suite = cipher_suite;
    slot.issued_at_ms = stamp_ms;
}

// Looks up a cached TLS 1.3 session ticket by opaque ticket identity bytes with
// full PSK (32 or 48 bytes) and cipher suite.
fn lookup_ticket_by_identity_full(
    ticket_id:        const u8[:],
    out_psk:          u8[..48]&,
    out_cipher_suite: u16&,
    now_ms:           i64 = 0,
) -> bool {
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out_psk[..]);
        out_psk.clear();
        out_cipher_suite = 0;
    };
    guard ticket_id.len > 0 else { return false; }
    let cur_ms = if now_ms > 0 { now_ms } else { core::unix_milli(core::now()) };
    for &entry in g_tls13_tickets {
        if entry.in_use && core::ct_eq_bytes(entry.ticket[..], ticket_id) {
            guard is_cached_ticket_fresh(entry, cur_ms) &&
                out_psk.try_set(entry.psk[..]) else { continue; }
            out_cipher_suite = entry.cipher_suite;
            committed = true;
            return true;
        }
    }
    return false;
}
