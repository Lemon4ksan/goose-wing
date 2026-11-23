// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dynamic Runtime SNI Multi-Certificate Registry & Wildcard Matcher (RFC 6066 Section 3, RFC 6125 Section 6.4.3).
namespace server;

import std;
import core;
import http.headers;
import tls.x509;
import tls.session;
import tls.pem;
import .internal;

// RFC 6066 Section 3: Server Name Indication - DNS HostName up to 253 ASCII bytes
const MAX_SNI_HOSTNAME_LEN: i64 = 253;

const MAX_SNI_DOMAINS: i64 = 64;

const MAX_SNI_CERT_PEM_LEN: i64 = 16384;

const MAX_SNI_KEY_PEM_LEN: i64 = 8192;

// Thread-local arena entry referencing PEM certificate and key byte spans in `g_sni_cert_arena` and `g_sni_key_arena`.
struct SniCertSlot {
    pattern:  u8[..255] = [],
    cert_off: i64       = 0,
    cert_len: i64       = 0,
    cert_cap: i64       = 0,
    key_off:  i64       = 0,
    key_len:  i64       = 0,
    key_cap:  i64       = 0,
    in_use:   bool      = false,
}

struct SniRegistryMeta {
    slots_off: i64  = 0,
    slots_cap: i64  = 0,
    active:    bool = false,
}

// Separate top-level resizable arrays avoid placing a `root struct` global on the worker thread-copy forbid list.
var g_sni_regs:       SniRegistryMeta[>..] = [];
var g_sni_slots:      SniCertSlot[>..]     = [];
var g_sni_cert_arena: u8[>..]              = [];
var g_sni_key_arena:  u8[>..]              = [];

// Fixed-size SNI registry handle referencing a lazily allocated slot in `g_sni_regs`.
struct SniRegistry {
    count:       i32 = 0,
    arena_slot:  i64 = -1,
    max_entries: i32 = 64,
}

struct SniCredentials {
    cert_pem: const u8[:] = "",
    key_pem:  const u8[:] = "",
}

inline fn sni_zeroize_slot_key(slot: SniCertSlot&) {
    guard slot.key_len > 0 && slot.key_off >= 0 else { return; }
    let end = core::add_sat_i64(slot.key_off, slot.key_len);
    if end <= g_sni_key_arena.len {
        core::secure_zeroize_slice(g_sni_key_arena[slot.key_off..end]);
    }
}

inline fn sni_clear_slot(slot: SniCertSlot&) {
    sni_zeroize_slot_key(slot);
    slot.in_use = false;
    slot.pattern.clear();
    slot.cert_len = 0;
    slot.key_len = 0;
}

fn sni_clear_meta_slots(meta: const SniRegistryMeta&) {
    let end = min(core::add_sat_i64(meta.slots_off, meta.slots_cap), g_sni_slots.len);
    var idx = max(meta.slots_off, 0);
    while idx < end {
        sni_clear_slot(g_sni_slots[idx]);
        idx = core::add_sat_i64(idx, 1);
    }
}

fn sni_ensure_arena_slot(reg: SniRegistry&) -> bool {
    if reg.arena_slot >= 0 {
        return reg.arena_slot < g_sni_regs.len && g_sni_regs[reg.arena_slot].active;
    }
    let want_cap: i64 = if reg.max_entries > 0 {
        min(reg.max_entries as i64, MAX_SNI_DOMAINS)
    } else {
        MAX_SNI_DOMAINS
    };
    for i in g_sni_regs.len {
        let meta .= g_sni_regs[i];
        if !meta.active && meta.slots_cap >= want_cap {
            sni_clear_meta_slots(meta);
            meta.active = true;
            reg.arena_slot = i;
            reg.count = 0;
            return true;
        }
    }
    let slots_off = g_sni_slots.len;
    for _ in want_cap {
        g_sni_slots.push(SniCertSlot { .. });
    }
    g_sni_regs.push(SniRegistryMeta {
        slots_off: slots_off,
        slots_cap: want_cap,
        active:    true,
    });
    reg.arena_slot = core::sub_sat_i64(g_sni_regs.len, 1);
    reg.count = 0;
    return true;
}

fn sni_store_slot_pems(
    slot:     SniCertSlot&,
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) {
    sni_zeroize_slot_key(slot);
    let cert_end = core::add_sat_i64(slot.cert_off, cert_pem.len);
    if cert_pem.len <= slot.cert_cap && slot.cert_off >= 0 && cert_end <= g_sni_cert_arena.len {
        core::ct_copy_bytes(g_sni_cert_arena[slot.cert_off..cert_end], cert_pem);
        slot.cert_len = cert_pem.len;
    } else {
        slot.cert_off = g_sni_cert_arena.len;
        g_sni_cert_arena.append(cert_pem);
        slot.cert_len = cert_pem.len;
        slot.cert_cap = cert_pem.len;
    }
    let key_end = core::add_sat_i64(slot.key_off, key_pem.len);
    if key_pem.len <= slot.key_cap && slot.key_off >= 0 && key_end <= g_sni_key_arena.len {
        core::ct_copy_bytes(g_sni_key_arena[slot.key_off..key_end], key_pem);
        slot.key_len = key_pem.len;
    } else {
        slot.key_off = g_sni_key_arena.len;
        g_sni_key_arena.append(key_pem);
        slot.key_len = key_pem.len;
        slot.key_cap = key_pem.len;
    }
}

inline fn sni_slot_credentials(slot: const SniCertSlot&) -> SniCredentials {
    let c_end = core::add_sat_i64(slot.cert_off, slot.cert_len);
    let k_end = core::add_sat_i64(slot.key_off, slot.key_len);
    guard slot.cert_off >= 0 && slot.cert_len > 0 && c_end <= g_sni_cert_arena.len &&
        slot.key_off >= 0 && slot.key_len > 0 && k_end <= g_sni_key_arena.len else {
        return SniCredentials { .. };
    }
    return SniCredentials {
        cert_pem: g_sni_cert_arena[slot.cert_off..c_end],
        key_pem:  g_sni_key_arena[slot.key_off..k_end],
    };
}

fn sni_find_exact_slot(meta: const SniRegistryMeta&, norm_name: const u8[:]) -> i64 {
    let end = min(core::add_sat_i64(meta.slots_off, meta.slots_cap), g_sni_slots.len);
    var idx = max(meta.slots_off, 0);
    while idx < end {
        let slot = &g_sni_slots[idx];
        if slot.in_use && tls::x509_strip_trailing_dot(slot.pattern[..]).eq_ascii_fold(norm_name) {
            return idx;
        }
        idx = core::add_sat_i64(idx, 1);
    }
    return -1;
}

fn sni_find_wildcard_slot(meta: const SniRegistryMeta&, norm_host: const u8[:]) -> i64 {
    let end = min(core::add_sat_i64(meta.slots_off, meta.slots_cap), g_sni_slots.len);
    var idx = max(meta.slots_off, 0);
    while idx < end {
        let slot = &g_sni_slots[idx];
        if slot.in_use {
            let pat = tls::x509_strip_trailing_dot(slot.pattern[..]);
            if pat.len >= 3 && pat[0] == '*' && pat[1] == '.' && tls::match_dns_san(pat, norm_host) {
                return idx;
            }
        }
        idx = core::add_sat_i64(idx, 1);
    }
    return -1;
}

fn sni_find_free_slot(meta: const SniRegistryMeta&) -> i64 {
    let end = min(core::add_sat_i64(meta.slots_off, meta.slots_cap), g_sni_slots.len);
    var idx = max(meta.slots_off, 0);
    while idx < end {
        if !g_sni_slots[idx].in_use {
            return idx;
        }
        idx = core::add_sat_i64(idx, 1);
    }
    return -1;
}

// Matches a hostname against an SNI domain pattern (RFC 6125 Section 6.4.3 & uWebSockets pattern).
// Supports exact domains ("example.com") and wildcard patterns ("*.example.com").
// Case-insensitive.
fn sni_pattern_matches(pattern: const u8[:], hostname: const u8[:]) -> bool {
    let p_norm = tls::x509_strip_trailing_dot(pattern);
    let h_norm = tls::x509_strip_trailing_dot(hostname);
    guard server_internal::is_valid_sni_pattern(p_norm) &&
        server_internal::is_valid_sni_hostname(h_norm) else {
        return false;
    }
    if p_norm.eq_ascii_fold(h_norm) {
        return true;
    }
    if p_norm.len >= 3 && p_norm[0] == '*' && p_norm[1] == '.' {
        return tls::match_dns_san(p_norm, h_norm);
    }
    return false;
}

// Zeroizes every private key span belonging to `reg`, marks its arena slot inactive for reuse,
// and resets `reg` to an unallocated empty state.
fn clear_sni_registry(reg: SniRegistry&) {
    if reg.arena_slot >= 0 && reg.arena_slot < g_sni_regs.len {
        let meta .= g_sni_regs[reg.arena_slot];
        sni_clear_meta_slots(meta);
        meta.active = false;
    }
    reg.count = 0;
    reg.arena_slot = -1;
}

// Registers or updates an SNI domain pattern with PEM certificate chain (<= 16 KiB) and key (<= 8 KiB)
// directly on a `SniRegistry` handle.
fn add_sni_registry_entry(
    reg:      SniRegistry&,
    pattern:  const u8[:],
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> bool {
    let p_norm = tls::x509_strip_trailing_dot(pattern);
    guard server_internal::is_valid_sni_pattern(p_norm) else { return false; }
    guard cert_pem.len > 0 && cert_pem.len <= MAX_SNI_CERT_PEM_LEN &&
        key_pem.len > 0 && key_pem.len <= MAX_SNI_KEY_PEM_LEN else {
        return false;
    }
    guard sni_ensure_arena_slot(reg) else { return false; }
    let meta = g_sni_regs[reg.arena_slot];
    let existing_idx = sni_find_exact_slot(meta, p_norm);
    if existing_idx >= 0 {
        sni_store_slot_pems(g_sni_slots[existing_idx], cert_pem, key_pem);
        return true;
    }
    guard reg.count < meta.slots_cap else { return false; }
    let free_idx = sni_find_free_slot(meta);
    guard free_idx >= 0 else { return false; }
    let slot .= g_sni_slots[free_idx];
    guard slot.pattern.try_set(p_norm) else { return false; }
    sni_store_slot_pems(slot, cert_pem, key_pem);
    slot.in_use = true;
    reg.count = core::add_sat_i64(reg.count, 1) as i32;
    return true;
}

// Removes a registered SNI domain pattern from `reg` and zeroizes its key span in `g_sni_key_arena`.
fn remove_sni_registry_entry(reg: SniRegistry&, pattern: const u8[:]) -> bool {
    let p_norm = tls::x509_strip_trailing_dot(pattern);
    guard p_norm.len > 0 && reg.count > 0 &&
        reg.arena_slot >= 0 && reg.arena_slot < g_sni_regs.len else {
        return false;
    }
    let meta = g_sni_regs[reg.arena_slot];
    guard meta.active else { return false; }
    let idx = sni_find_exact_slot(meta, p_norm);
    guard idx >= 0 else { return false; }
    sni_clear_slot(g_sni_slots[idx]);
    reg.count = core::sub_sat_i64(reg.count, 1) as i32;
    return true;
}

// Resolves TLS credentials from `reg` using exact match first, then wildcard (RFC 6125 Section 6.4.3).
fn resolve_sni_registry(
    reg:          const SniRegistry&,
    sni_hostname: const u8[:],
) -> SniCredentials, bool {
    let h_norm = tls::x509_strip_trailing_dot(sni_hostname);
    guard reg.count > 0 &&
        reg.arena_slot >= 0 &&
        reg.arena_slot < g_sni_regs.len &&
        server_internal::is_valid_sni_hostname(h_norm) else {
        return SniCredentials { .. }, false;
    }
    let meta = g_sni_regs[reg.arena_slot];
    guard meta.active else { return SniCredentials { .. }, false; }

    let exact_idx = sni_find_exact_slot(meta, h_norm);
    if exact_idx >= 0 {
        return sni_slot_credentials(g_sni_slots[exact_idx]), true;
    }
    let wild_idx = sni_find_wildcard_slot(meta, h_norm);
    if wild_idx >= 0 {
        return sni_slot_credentials(g_sni_slots[wild_idx]), true;
    }
    return SniCredentials { .. }, false;
}

// Registers or updates an SNI domain pattern with certificate and private key credentials.
// Supports exact domains and wildcard patterns (uWebSockets app.addServerName).
fn add_server_name<S>(
    server:   S&,
    pattern:  const u8[:],
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> bool {
    return add_sni_registry_entry(server.sni_registry, pattern, cert_pem, key_pem);
}

// Removes a previously registered SNI domain pattern (uWebSockets app.removeServerName).
fn remove_server_name<S>(server: S&, pattern: const u8[:]) -> bool {
    return remove_sni_registry_entry(server.sni_registry, pattern);
}

// Resolves TLS credentials for an SNI hostname using exact match first, then wildcard (RFC 6125 Section 6.4.3).
// Returns (SniCredentials, ok).
fn resolve_sni_credentials<S>(
    server:       const S&,
    sni_hostname: const u8[:],
) -> SniCredentials, bool {
    return resolve_sni_registry(server.sni_registry, sni_hostname);
}

// Resolves TLS credentials for an SNI hostname with fallback handler for missing server names
// (uWebSockets app.missingServerName pattern).
fn resolve_sni_credentials_with_fallback<S, Fallback: fn(const u8[:]) -> SniCredentials>(
    server:       const S&,
    sni_hostname: const u8[:],
) -> SniCredentials, bool {
    let creds, ok = resolve_sni_credentials(server, sni_hostname);
    if ok { return creds, true; }
    let fb_creds = Fallback(sni_hostname);
    if fb_creds.cert_pem.len > 0 {
        return fb_creds, true;
    }
    return SniCredentials { .. }, false;
}

// Decodes PEM certificate and private key from resolved SNI credentials into a TLS server config.
fn sni_credentials_to_tls_config(
    creds:   const SniCredentials&,
    out_cfg: tls::ServerHandshakeConfig&,
) -> bool {
    return tls::load_server_credentials_pem(creds.cert_pem, creds.key_pem, out_cfg);
}
