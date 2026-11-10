// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dynamic Runtime SNI Multi-Certificate Registry & Wildcard Matcher (RFC 6066 §3, RFC 6125 §6.4.3).
namespace wing;

import std;
import core from "..";
import http.headers;
import tls.x509;

// Dynamic Runtime SNI multi-certificate credentials (uWebSockets addServerName / removeServerName pattern).
struct SniCertEntry {
    pattern:  u8[..128]  = [],
    cert_pem: u8[..4096] = [],
    key_pem:  u8[..4096] = [],
    in_use:   bool       = false,
}

const MAX_SNI_DOMAINS: i64 = 32;

struct SniRegistry {
    entries: SniCertEntry[32] = [SniCertEntry { .. }; 32],
    count:   i32              = 0,
}

struct SniCredentials {
    cert_pem: const u8[:] = "",
    key_pem:  const u8[:] = "",
}

inline fn is_valid_sni_pattern(p_norm: const u8[:]) -> bool {
    guard p_norm.len > 0 && p_norm.len <= 128 && p_norm != "*" else { return false; }
    guard !x509_is_ip_literal(p_norm) && !p_norm.contains_byte(':') else { return false; }
    if p_norm[0] == '*' {
        guard p_norm.len >= 3 && p_norm[1] == '.' && p_norm[2..].contains_byte('.') else {
            return false;
        }
    }
    return validate_san_dns_name(p_norm);
}

inline fn is_valid_sni_hostname(h_norm: const u8[:]) -> bool {
    guard h_norm.len > 0 && !h_norm.contains_byte('*') else { return false; }
    guard !x509_is_ip_literal(h_norm) && !h_norm.contains_byte(':') else { return false; }
    return validate_san_dns_name(h_norm);
}

// Matches a hostname against an SNI domain pattern (RFC 6125 §6.4.3 & uWebSockets pattern).
// Supports exact domains ("example.com") and wildcard patterns ("*.example.com").
// Case-insensitive.
fn sni_pattern_matches(pattern: const u8[:], hostname: const u8[:]) -> bool {
    let p_norm = x509_strip_trailing_dot(pattern);
    let h_norm = x509_strip_trailing_dot(hostname);
    guard is_valid_sni_pattern(p_norm) && is_valid_sni_hostname(h_norm) else { return false; }
    if p_norm.eq_ascii_fold(h_norm) {
        return true;
    }
    if p_norm.len >= 3 && p_norm[0] == '*' && p_norm[1] == '.' {
        return match_dns_san(p_norm, h_norm);
    }
    return false;
}

// Registers or updates an SNI domain pattern with certificate and private key credentials.
// Supports exact domains and wildcard patterns (uWebSockets app.addServerName).
fn add_server_name<S>(
    server:   S&,
    pattern:  const u8[:],
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> bool {
    let p_norm = x509_strip_trailing_dot(pattern);
    guard is_valid_sni_pattern(p_norm) else { return false; }
    guard cert_pem.len > 0 && cert_pem.len <= 4096 && key_pem.len > 0 && key_pem.len <= 4096 else {
        return false;
    }

    // Check if pattern already registered: update in place
    for i in server.sni_registry.entries.len {
        let entry_pat = x509_strip_trailing_dot(server.sni_registry.entries[i].pattern[..]);
        if server.sni_registry.entries[i].in_use && entry_pat.eq_ascii_fold(p_norm) {
            core::secure_zeroize_slice(server.sni_registry.entries[i].key_pem[..]);
            let _ = server.sni_registry.entries[i].cert_pem.try_set(cert_pem);
            let _ = server.sni_registry.entries[i].key_pem.try_set(key_pem);
            return true;
        }
    }

    // Find first empty slot
    guard server.sni_registry.count < server.sni_registry.entries.len as i32 else { return false; }
    for i in server.sni_registry.entries.len {
        if !server.sni_registry.entries[i].in_use {
            let _ = server.sni_registry.entries[i].pattern.try_set(p_norm);
            let _ = server.sni_registry.entries[i].cert_pem.try_set(cert_pem);
            let _ = server.sni_registry.entries[i].key_pem.try_set(key_pem);
            server.sni_registry.entries[i].in_use = true;
            server.sni_registry.count = core::add_sat_i64(server.sni_registry.count, 1) as i32;
            return true;
        }
    }
    return false;
}

// Removes a previously registered SNI domain pattern (uWebSockets app.removeServerName).
fn remove_server_name<S>(server: S&, pattern: const u8[:]) -> bool {
    let p_norm = x509_strip_trailing_dot(pattern);
    guard p_norm.len > 0 && server.sni_registry.count > 0 else { return false; }
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        if entry.in_use && x509_strip_trailing_dot(entry.pattern[..]).eq_ascii_fold(p_norm) {
            entry.in_use = false;
            entry.pattern.clear();
            entry.cert_pem.clear();
            core::secure_zeroize_slice(entry.key_pem[..]);
            entry.key_pem.clear();
            server.sni_registry.count = core::sub_sat_i64(server.sni_registry.count, 1) as i32;
            return true;
        }
    }
    return false;
}

// Resolves TLS credentials for an SNI hostname using exact match first, then wildcard (RFC 6125 §6.4.3).
// Returns (SniCredentials, ok).
fn resolve_sni_credentials<S>(
    server:       const S&,
    sni_hostname: const u8[:],
) -> SniCredentials, bool {
    let h_norm = x509_strip_trailing_dot(sni_hostname);
    guard server.sni_registry.count > 0 && is_valid_sni_hostname(h_norm) else {
        return SniCredentials { .. }, false;
    }

    // Phase 1: Exact match priority
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        if entry.in_use && x509_strip_trailing_dot(entry.pattern[..]).eq_ascii_fold(h_norm) {
            return SniCredentials {
                cert_pem: entry.cert_pem[..],
                key_pem:  entry.key_pem[..],
            }, true;
        }
    }

    // Phase 2: Wildcard match (*.domain.com)
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        guard entry.in_use else { continue; }
        let pat = x509_strip_trailing_dot(entry.pattern[..]);
        guard pat.len >= 3 && pat[0] == '*' && pat[1] == '.' else { continue; }
        if match_dns_san(pat, h_norm) {
            return SniCredentials {
                cert_pem: entry.cert_pem[..],
                key_pem:  entry.key_pem[..],
            }, true;
        }
    }

    return SniCredentials { .. }, false;
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
