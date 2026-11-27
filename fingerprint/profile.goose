// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wing Profile and Persona Engine.
// Enforces Wing's authentic zero-heap identity by default, with user-level control
// over headers, TLS parameters, Akamai HTTP/2, p0f v3, and JA4/JA4H generation.
namespace fingerprint;

import std;
import core;
import rfc.tls;
import rfc.h2;
import http.headers;
import .types;
import .ja4;
import .p0f;
import .akamai;

// ---- Profile Metadata ------------------------------------------------------

// Returns the canonical User-Agent string associated with a `Profile` preset.
fn user_agent(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing/1.0 (Goose Zero-Heap Systems Engine) NetStack/7.0",
        Custom => "Wing/1.0 (Custom Profile)",
        None => "goose-wing/0.1",
        _ => "Wing/1.0",
    };
}

// Returns the display name of a `Profile` preset.
fn name(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing",
        Custom => "Custom",
        None => "None",
        _ => "Wing",
    };
}

// ---- Profile Constructors --------------------------------------------------

// Constructs the authentic Wing profile with modern TLS 1.3/1.2 suites, HTTP/2, HTTP/3, and p0f specs.
fn wing_default_profile() -> ClientProfile {
    var p = ClientProfile {
        kind:   Profile.Wing,
        h2:     H2Settings { .. },
        h3:     H3Settings { .. },
        tls:    TlsFingerprintSpec { .. },
        p0f:    wing_p0f_signature(),
        akamai: akamai_wing_preset(),
        ..
    };

    p.user_agent.append("Wing/1.0 (Goose Zero-Heap Systems Engine) NetStack/7.0");

    // Standard content negotiation (advertising native RFC 8878 Zstandard)
    p.accept.append("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
    p.accept_encoding.append("zstd, gzip, br");
    p.accept_language.append("en-US,en;q=0.9");
    p.upgrade_insecure_requests.append("1");

    // Wing TLS Spec: Pure modern high-security suites (clean, deterministic)
    p.tls.supported_versions.push(0x0304); // TLS 1.3
    p.tls.supported_versions.push(0x0303); // TLS 1.2

    // TLS 1.3 & TLS 1.2 Cipher Suites
    p.tls.ciphers.push(0x1301); // TLS_AES_128_GCM_SHA256
    p.tls.ciphers.push(0x1302); // TLS_AES_256_GCM_SHA384
    p.tls.ciphers.push(0x1303); // TLS_CHACHA20_POLY1305_SHA256
    p.tls.ciphers.push(0xc02b); // ECDHE-ECDSA-AES128-GCM-SHA256
    p.tls.ciphers.push(0xc02f); // ECDHE-RSA-AES128-GCM-SHA256
    p.tls.ciphers.push(0xc02c); // ECDHE-ECDSA-AES256-GCM-SHA384
    p.tls.ciphers.push(0xc030); // ECDHE-RSA-AES256-GCM-SHA384
    p.tls.ciphers.push(0xcca8); // ECDHE-RSA-CHACHA20-POLY1305
    p.tls.ciphers.push(0xcca9); // ECDHE-ECDSA-CHACHA20-POLY1305

    // TLS Extensions (canonical wire order)
    p.tls.extensions.push(0x0000); // server_name (SNI)
    p.tls.extensions.push(0x000a); // supported_groups
    p.tls.extensions.push(0x000b); // ec_point_formats
    p.tls.extensions.push(0x000d); // signature_algorithms
    p.tls.extensions.push(0x0010); // ALPN
    p.tls.extensions.push(0x0017); // extended_master_secret
    p.tls.extensions.push(0x001b); // compress_certificate
    p.tls.extensions.push(0x002b); // supported_versions
    p.tls.extensions.push(0x002d); // psk_key_exchange_modes
    p.tls.extensions.push(0x0033); // key_share

    // Signature Algorithms
    p.tls.sig_algorithms.push(0x0403); // ecdsa_secp256r1_sha256
    p.tls.sig_algorithms.push(0x0804); // rsa_pss_rsae_sha256
    p.tls.sig_algorithms.push(0x0401); // rsa_pkcs1_sha256
    p.tls.sig_algorithms.push(0x0503); // ecdsa_secp384r1_sha384
    p.tls.sig_algorithms.push(0x0805); // rsa_pss_rsae_sha384
    p.tls.sig_algorithms.push(0x0501); // rsa_pkcs1_sha384
    p.tls.sig_algorithms.push(0x0806); // rsa_pss_rsae_sha512
    p.tls.sig_algorithms.push(0x0601); // rsa_pkcs1_sha512

    p.tls.alpn.append("h2");
    let _ = validate_and_filter_profile(p);
    return p;
}

// Returns true only for PFS + AEAD TLS 1.3 and TLS 1.2 cipher suites (RFC 9113 Section 9.2.2).
// Rejects RSA key exchange, CBC, SHA-1, RC4, 3DES, NULL, and export/weak suites.
fn is_allowed_tls_cipher(cipher_id: u16) -> bool {
    return match cipher_id {
        0x1301 => true, // TLS_AES_128_GCM_SHA256
        0x1302 => true, // TLS_AES_256_GCM_SHA384
        0x1303 => true, // TLS_CHACHA20_POLY1305_SHA256
        0x1304 => true, // TLS_AES_128_CCM_SHA256
        0xC02B => true, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02C => true, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC02F => true, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030 => true, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xCCA8 => true, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xCCA9 => true, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0x009E => true, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009F => true, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0xCCAA => true, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        _ => false,
    };
}

inline fn filter_profile_ciphers(ciphers: u16[..32]&) -> bool {
    let had_ciphers = ciphers.len > 0;
    var filtered:   u16[..32] = [];
    var real_count: i64       = 0;
    for c in ciphers {
        let is_g = rfc::is_grease_u16(c);
        guard is_g || is_allowed_tls_cipher(c) else { continue; }
        if !filtered.contains(c) && filtered.try_push(c) && !is_g {
            real_count = core::add_sat_i64(real_count, 1);
        }
    }
    ciphers = filtered;
    return !had_ciphers || real_count > 0;
}

inline fn filter_profile_versions(versions: u16[..8]&) -> bool {
    let had_versions = versions.len > 0;
    var filtered:   u16[..8] = [];
    var real_count: i64      = 0;
    for v in versions {
        let is_g = rfc::is_grease_u16(v);
        guard is_g || v == 0x0304 || v == 0x0303 else { continue; }
        if !filtered.contains(v) && filtered.try_push(v) && !is_g {
            real_count = core::add_sat_i64(real_count, 1);
        }
    }
    versions = filtered;
    return !had_versions || real_count > 0;
}

// Strips disallowed TLS cipher suites and pre-TLS 1.2 versions from `profile`.
// Returns false if a non-empty cipher or version list contains zero valid entries after filtering.
fn validate_and_filter_profile(profile: ClientProfile&) -> bool {
    let ok_ciphers = filter_profile_ciphers(profile.tls.ciphers);
    let ok_versions = filter_profile_versions(profile.tls.supported_versions);
    return ok_ciphers && ok_versions;
}

inline fn grease_u16_from_nibble(idx: u64) -> u16 {
    let nib = (idx & 0x0F) as u16;
    let b = (nib << 4) | 0x0A;
    return (b << 8) | b;
}

inline fn prepend_grease_u16<B>(list: B&, grease_val: u16) {
    var rebuilt = copy(list);
    list.clear();
    let _ = list.try_push(grease_val);
    for v in rebuilt {
        if !rfc::is_grease_u16(v) {
            let _ = list.try_push(v);
        }
    }
}

// Rotates distinct RFC 8701 GREASE values across `ciphers`, `extensions`, and `supported_versions`.
fn rotate_profile_grease(profile: ClientProfile&, seed: u64) {
    var buf: u8[9] = [0; 9];
    core::write_le_u64_at(buf[..], 0, seed);
    let i0 = core::fnv1a_64(buf[..]) % 16;
    buf[8] = 1;
    let i1 = (i0 + 1 + (core::fnv1a_64(buf[..]) % 15)) % 16;
    buf[8] = 2;
    var i2 = core::fnv1a_64(buf[..]) % 16;
    for _ in 2 {
        if i2 == i0 || i2 == i1 {
            i2 = (i2 + 1) % 16;
        }
    }
    prepend_grease_u16(profile.tls.ciphers, grease_u16_from_nibble(i0));
    prepend_grease_u16(profile.tls.extensions, grease_u16_from_nibble(i1));
    prepend_grease_u16(profile.tls.supported_versions, grease_u16_from_nibble(i2));
}

// Constructs a completely custom, blank persona for full user control.
fn custom_profile() -> ClientProfile {
    var p = ClientProfile {
        kind: Profile.Custom,
        ..
    };
    let _ = validate_and_filter_profile(p);
    return p;
}

// Constructs a minimal / bare profile without default headers.
fn none_profile() -> ClientProfile {
    return ClientProfile {
        kind: Profile.None,
        ..
    };
}

// Constructs a profile according to the specified Profile enum.
fn new_client_profile(kind: Profile) -> ClientProfile {
    if kind == Profile.Custom {
        return custom_profile();
    } else if kind == Profile.None {
        return none_profile();
    }
    return wing_default_profile();
}

// ---- Fingerprint Computation & Profile Mutators ----------------------------

// Computes the FoxIO JA4 TLS fingerprint for this profile.
fn ja4(profile: const ClientProfile&, opts: Ja4Options = Ja4Options { .. }) -> u8[..64] {
    return compute_ja4(
        profile.tls.ciphers[..],
        profile.tls.extensions[..],
        profile.tls.supported_versions[..],
        opts.sni,
        profile.tls.alpn[..],
        profile.tls.sig_algorithms[..],
        opts.is_quic,
    );
}

// Computes the FoxIO JA4H HTTP client fingerprint for this profile under given method and parameters.
fn ja4h(
    profile:       const ClientProfile&,
    method:        const u8[:],
    proto:         const u8[:],
    opts:          Ja4hOptions    = Ja4hOptions { .. },
    cookie_names:  const u8[:][:] = [],
    cookie_values: const u8[:][:] = [],
) -> u8[..64] {
    // 5 standard profile headers + HeaderMap max 128 entries = 133 max.
    var header_names: const u8[:][..136] = [];
    if profile.user_agent.len > 0 { let _ = header_names.try_push("user-agent"); }
    if profile.accept.len > 0 { let _ = header_names.try_push("accept"); }
    if profile.accept_encoding.len > 0 { let _ = header_names.try_push("accept-encoding"); }
    if profile.accept_language.len > 0 { let _ = header_names.try_push("accept-language"); }
    if profile.upgrade_insecure_requests.len > 0 { let _ = header_names.try_push("upgrade-insecure-requests"); }

    for &e in profile.extra_headers.entries {
        let _ = header_names.try_push(profile.extra_headers.entry_name(e));
    }

    return compute_ja4h(
        method,
        proto,
        header_names[..],
        Ja4hFlags { has_cookie: opts.has_cookie, has_referer: opts.has_referer },
        profile.accept_language[..],
        cookie_names,
        cookie_values,
    );
}

// Adds or overrides a header in the profile.
fn set_header(profile: ClientProfile&, name: const u8[:], value: const u8[:]) {
    if name.eq_ascii_fold("user-agent") {
        set_user_agent(profile, value);
        return;
    }
    if name.eq_ascii_fold("accept") {
        set_accept(profile, value);
        return;
    }
    if name.eq_ascii_fold("accept-encoding") {
        set_accept_encoding(profile, value);
        return;
    }
    if name.eq_ascii_fold("accept-language") {
        set_accept_language(profile, value);
        return;
    }
    if name.eq_ascii_fold("upgrade-insecure-requests") {
        let _ = profile.upgrade_insecure_requests.try_set(value);
        return;
    }
    profile.extra_headers.set_header(name, value);
}

// Sets a custom User-Agent in the profile.
fn set_user_agent(profile: ClientProfile&, ua: const u8[:]) {
    let _ = profile.user_agent.try_set(ua);
}

// Sets Accept header in the profile.
fn set_accept(profile: ClientProfile&, accept_str: const u8[:]) {
    let _ = profile.accept.try_set(accept_str);
}

// Sets Accept-Encoding header in the profile.
fn set_accept_encoding(profile: ClientProfile&, enc: const u8[:]) {
    let _ = profile.accept_encoding.try_set(enc);
}

// Sets Accept-Language header in the profile.
fn set_accept_language(profile: ClientProfile&, lang: const u8[:]) {
    let _ = profile.accept_language.try_set(lang);
}

// Configures the p0f TCP SYN signature for this profile.
fn set_p0f(profile: ClientProfile&, sig: const P0fSignature&) {
    profile.p0f = sig;
}

// Computes the p0f v3 format string for this profile.
fn format_p0f(profile: const ClientProfile&) -> u8[..256] {
    return format_p0f(profile.p0f);
}

// Configures the Akamai HTTP/2 fingerprint for this profile and resets omitted H2Settings fields cleanly.
fn set_akamai(profile: ClientProfile&, fp: const AkamaiFingerprint&) {
    profile.akamai = fp;
    profile.h2 = H2Settings { .. };
    for &s in fp.settings {
        if s.id == rfc::H2_SETTING_HEADER_TABLE_SIZE { profile.h2.header_table_size = s.val; }
        else if s.id == rfc::H2_SETTING_ENABLE_PUSH { profile.h2.enable_push = s.val; }
        else if s.id == rfc::H2_SETTING_MAX_CONCURRENT_STREAMS { profile.h2.max_concurrent_streams = s.val; }
        else if s.id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE { profile.h2.initial_window_size = s.val; }
        else if s.id == rfc::H2_SETTING_MAX_FRAME_SIZE { profile.h2.max_frame_size = s.val; }
        else if s.id == rfc::H2_SETTING_MAX_HEADER_LIST_SIZE { profile.h2.max_header_list_size = s.val; }
    }
}

// Formats the Akamai HTTP/2 fingerprint string for this profile.
fn format_akamai(profile: const ClientProfile&) -> u8[..640] {
    return format_akamai(profile.akamai);
}

// Computes the 32-character hexadecimal MD5 Akamai hash for this profile.
fn akamai_hash(profile: const ClientProfile&) -> u8[..32] {
    return akamai_hash(profile.akamai);
}
