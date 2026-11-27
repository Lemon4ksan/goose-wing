// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal STEK selection, plaintext unpacking, and session ticket cache storage (RFC 8446 §4.6.1).
namespace tls_internal;

import std;
import core;
import .internal;
import .types;

var g_tls13_client_tickets: tls::CachedSessionTicket[16] = [tls::CachedSessionTicket { .. }; 16];

var g_tls13_server_tickets: tls::CachedSessionTicket[16] = [tls::CachedSessionTicket { .. }; 16];

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
    guard rfc::is_supported_tls13_cipher_suite(cs) &&
        psk_len == rfc::tls13_cipher_suite_hash_len(cs) &&
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

inline fn compute_alpn_scope_hash(alpn_csv: const u8[:]) -> u64 {
    guard alpn_csv.len > 0 else { return 0; }
    return core::fnv1a_64(alpn_csv);
}

fn sha256_update_trust_store(ctx: core::Sha256Ctx&, store: const tls::TrustAnchorStore&) {
    var hdr: u8[8] = [0; 8];
    core::write_le_u64_at(hdr[..], 0, store.anchors.len as u64);
    core::sha256_update(ctx, hdr[..]);
    for &a in store.anchors {
        let valid_b: u8[1] = [if a.is_valid { 1 } else { 0 }];
        core::sha256_update(ctx, valid_b[..]);
        core::sha256_update(ctx, a.subject_dn_sha256[..]);
        core::sha256_update(ctx, a.spki_sha256[..]);
        core::sha256_update(ctx, a.cert_der_sha256[..]);
    }
}

fn compute_trust_store_policy_hash(store: const tls::TrustAnchorStore&) -> u64 {
    guard store.anchors.len > 0 else { return 0; }
    var ctx = core::Sha256Ctx { .. };
    sha256_update_trust_store(ctx, store);
    let dig = core::sha256_final(ctx);
    return core::read_le_u64(dig[..], 0);
}

fn compute_client_policy_hash(cfg: const tls::ClientHandshakeConfig&) -> u64 {
    var ctx = core::Sha256Ctx { .. };
    var hdr: u8[24] = [0; 24];
    hdr[0] = if cfg.insecure_skip_verify { 1 } else { 0 };
    hdr[1] = if cfg.use_system_roots { 1 } else { 0 };
    hdr[2] = if cfg.require_ocsp_stapling { 1 } else { 0 };
    hdr[3] = if cfg.enable_pq_hybrid { 1 } else { 0 };
    core::write_le_u64_at(hdr[..], 4, cfg.expired_leaf_grace_sec as u64);
    core::write_le_u32_at(hdr[..], 12, cfg.crl_der.len as u32);
    core::write_le_u32_at(hdr[..], 16, cfg.client_cert_der.len as u32);
    core::write_le_u32_at(hdr[..], 20, cfg.trust_store.anchors.len as u32);
    core::sha256_update(ctx, hdr[..]);
    if cfg.crl_der.len > 0 { core::sha256_update(ctx, cfg.crl_der[..]); }
    if cfg.client_cert_der.len > 0 { core::sha256_update(ctx, cfg.client_cert_der[..]); }
    sha256_update_trust_store(ctx, cfg.trust_store);
    let dig = core::sha256_final(ctx);
    return core::read_le_u64(dig[..], 0);
}

inline fn populate_cached_ticket_slot(
    slot:                 tls::CachedSessionTicket&,
    server_name:          const u8[:],
    ticket:               const u8[:],
    psk:                  const u8[:],
    age_add:              u32,
    lifetime:             u32,
    cipher_suite:         u16,
    stamp_ms:             i64,
    client_authenticated: bool = false,
    port:                 u16  = 0,
    tenant_hash:          u64  = 0,
    alpn_hash:            u64  = 0,
    policy_hash:          u64  = 0,
    ca_policy_hash:       u64  = 0,
) {
    core::secure_zeroize_slice(slot.psk[..]);
    slot.in_use = true;
    slot.client_authenticated = client_authenticated;
    let _ = slot.server_name.try_set(server_name);
    let _ = slot.ticket.try_set(ticket);
    let _ = slot.psk.try_set(psk);
    slot.age_add = age_add;
    slot.lifetime = lifetime;
    slot.cipher_suite = cipher_suite;
    slot.issued_at_ms = stamp_ms;
    slot.port = port;
    slot.tenant_hash = tenant_hash;
    slot.alpn_hash = alpn_hash;
    slot.policy_hash = policy_hash;
    slot.ca_policy_hash = ca_policy_hash;
}

// Stores a server-issued TLS 1.3 resumption ticket in the isolated server table with mTLS and CA policy binding.
fn store_server_session_ticket(
    server_name:          const u8[:],
    ticket:               const u8[:],
    psk:                  const u8[:],
    age_add:              u32,
    lifetime:             u32,
    cipher_suite:         u16  = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    client_authenticated: bool = false,
    issued_at_ms:         i64  = 0,
    ca_policy_hash:       u64  = 0,
) {
    guard server_name.len > 0 && server_name.len <= 255 else { return; }
    guard ticket.len > 0 && ticket.len <= 1536 &&
        lifetime > 0 && lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else {
        return;
    }
    guard rfc::is_supported_tls13_cipher_suite(cipher_suite) &&
        psk.len == rfc::tls13_cipher_suite_hash_len(cipher_suite) else {
        return;
    }
    let stamp_ms = if issued_at_ms > 0 { issued_at_ms } else { core::unix_milli(core::now()) };
    native_tls_state_lock(TLS_LOCK_TICKET_CACHE);
    defer native_tls_state_unlock(TLS_LOCK_TICKET_CACHE);
    for &entry in g_tls13_server_tickets {
        if entry.in_use && core::ct_eq_bytes(entry.ticket[..], ticket) {
            populate_cached_ticket_slot(
                entry, server_name, ticket, psk, age_add, lifetime,
                cipher_suite, stamp_ms, client_authenticated, 0, 0, 0, 0, ca_policy_hash,
            );
            return;
        }
    }
    for &entry in g_tls13_server_tickets {
        if !entry.in_use {
            populate_cached_ticket_slot(
                entry, server_name, ticket, psk, age_add, lifetime,
                cipher_suite, stamp_ms, client_authenticated, 0, 0, 0, 0, ca_policy_hash,
            );
            return;
        }
    }
    populate_cached_ticket_slot(
        g_tls13_server_tickets[0], server_name, ticket, psk, age_add,
        lifetime, cipher_suite, stamp_ms, client_authenticated, 0, 0, 0, 0, ca_policy_hash,
    );
}

// Looks up a server-issued TLS 1.3 session ticket by opaque ticket identity bytes.
// Enforces server-only table isolation, SNI binding, cipher-suite hash-length match, mTLS, and CA policy binding.
fn lookup_server_ticket_by_identity(
    ticket_id:           const u8[:],
    require_client_cert: bool,
    out_psk:             u8[..48]&,
    out_cipher_suite:    u16&,
    now_ms:              i64         = 0,
    server_name:         const u8[:] = "",
    ca_policy_hash:      u64         = 0,
) -> bool {
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out_psk[..]);
        out_psk.clear();
        out_cipher_suite = 0;
    };
    guard ticket_id.len > 0 else { return false; }
    let cur_ms = if now_ms > 0 { now_ms } else { core::unix_milli(core::now()) };
    native_tls_state_lock(TLS_LOCK_TICKET_CACHE);
    defer native_tls_state_unlock(TLS_LOCK_TICKET_CACHE);
    for &entry in g_tls13_server_tickets {
        guard entry.in_use && core::ct_eq_bytes(entry.ticket[..], ticket_id) else { continue; }
        let expected_hlen = rfc::tls13_cipher_suite_hash_len(entry.cipher_suite) as i64;
        guard is_cached_ticket_fresh(entry, cur_ms) &&
            entry.server_name[..].eq_ascii_fold(server_name) &&
            entry.ca_policy_hash == ca_policy_hash &&
            (!require_client_cert || entry.client_authenticated) &&
            entry.psk.len == expected_hlen &&
            out_psk.try_set(entry.psk[..]) else {
            continue;
        }
        out_cipher_suite = entry.cipher_suite;
        committed = true;
        return true;
    }
    return false;
}

// Computes RFC 8446 Section 4.2.11.1 obfuscated_ticket_age = ((now_ms - issued_at_ms) + age_add) mod 2^32.
inline fn compute_obfuscated_ticket_age(cur_ms: i64, issued_at_ms: i64, age_add: u32) -> u32 {
    let elapsed_ms = core::sub_sat_i64(cur_ms, issued_at_ms);
    let elapsed_u64 = (if elapsed_ms > 0 { elapsed_ms } else { 0 }) as u64;
    let sum = core::add_sat_u64(elapsed_u64 & 0xFFFFFFFF, age_add);
    return (sum & 0xFFFFFFFF) as u32;
}

// Looks up a client-cached TLS 1.3 session ticket scoped by `(server_name, port, tenant_hash, alpn_hash, policy_hash)`
// and computes RFC 8446 Section 4.2.11.1 obfuscated_ticket_age.
fn lookup_client_ticket_for_ch<B>(
    server_name:        const u8[:],
    out_ticket:         B&,
    out_psk:            u8[..48]&,
    out_obfuscated_age: u32&,
    out_cipher_suite:   u16&,
    now_ms:             i64 = 0,
    port:               u16 = 0,
    tenant_hash:        u64 = 0,
    alpn_hash:          u64 = 0,
    policy_hash:        u64 = 0,
) -> bool {
    var committed = false;
    defer if !committed {
        out_ticket.clear();
        core::secure_zeroize_slice(out_psk[..]);
        out_psk.clear();
        out_obfuscated_age = 0;
        out_cipher_suite = 0;
    };
    guard server_name.len > 0 else { return false; }
    let cur_ms = if now_ms > 0 { now_ms } else { core::unix_milli(core::now()) };
    native_tls_state_lock(TLS_LOCK_TICKET_CACHE);
    defer native_tls_state_unlock(TLS_LOCK_TICKET_CACHE);
    for &entry in g_tls13_client_tickets {
        guard entry.in_use &&
            entry.server_name[..] == server_name &&
            entry.port == port &&
            entry.tenant_hash == tenant_hash &&
            entry.alpn_hash == alpn_hash &&
            entry.policy_hash == policy_hash else {
            continue;
        }
        guard is_cached_ticket_fresh(entry, cur_ms) &&
            out_ticket.try_set(entry.ticket[..]) &&
            out_psk.try_set(entry.psk[..]) else {
            continue;
        }
        out_obfuscated_age = compute_obfuscated_ticket_age(cur_ms, entry.issued_at_ms, entry.age_add);
        out_cipher_suite = entry.cipher_suite;
        committed = true;
        return true;
    }
    return false;
}
