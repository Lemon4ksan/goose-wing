// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wing Profile and Persona Engine.
// Enforces Wing's authentic zero-heap identity by default, with complete user-level
// control over headers, meta-headers, TLS parameters, and JA4 fingerprint generation.
namespace wing;

import std;
import core from "..";
import http.headers;
import fingerprint.ja4;
import fingerprint.p0f;
import fingerprint.akamai;

// ---- client profiles -------------------------------------------------------

enum Profile {
    Wing,   // Authentic Wing Zero-Heap Systems Engine identity (Default)
    Custom, // User-controlled custom profile
    None,   // Minimal raw client without default headers
}

fn profile_user_agent(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing/1.0 (Goose Zero-Heap Systems Engine) NetStack/7.0",
        Custom => "Wing/1.0 (Custom Profile)",
        None => "goose-wing/0.1",
        _ => "Wing/1.0",
    };
}

fn profile_name(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing",
        Custom => "Custom",
        None => "None",
        _ => "Wing",
    };
}

// HTTP/2 protocol settings for the persona.
struct H2Settings {
    header_table_size:      u32 = 65536,
    enable_push:            u32 = 0,
    max_concurrent_streams: u32 = 100,
    initial_window_size:    u32 = 6291456,
    max_frame_size:         u32 = 16384,
    max_header_list_size:   u32 = 262144,
}

// HTTP/3 protocol settings for the persona.
struct H3Settings {
    qpack_max_table_capacity:  u64 = 4096,
    max_field_section_size:    u64 = 65536,
    qpack_blocked_streams:     u64 = 16,
    enable_connect_protocol:   u64 = 1,
    h3_datagram:               u64 = 0,
    enable_webtransport:       u64 = 0,
    webtransport_max_sessions: u64 = 0,
}

// TLS ClientHello specification for JA4 fingerprinting and transport configuration.
struct TlsFingerprintSpec {
    ciphers:            u16[..32] = [],
    extensions:         u16[..32] = [],
    supported_versions: u16[..8]  = [],
    sig_algorithms:     u16[..16] = [],
    alpn:               u8[..16]  = [],
}

// Client profile specification governing outbound request appearance and wire fingerprint.
struct ClientProfile {
    kind:                      Profile            = Profile.Wing,
    user_agent:                u8[..256]          = [],
    accept:                    u8[..192]          = [],
    accept_encoding:           u8[..64]           = [],
    accept_language:           u8[..64]           = [],
    upgrade_insecure_requests: u8[..8]            = [],
    extra_headers:             HeaderMap          = HeaderMap { .. },
    header_order:              u8[..32][..64]     = [],
    h2:                        H2Settings         = H2Settings { .. },
    h3:                        H3Settings         = H3Settings { .. },
    tls:                       TlsFingerprintSpec = TlsFingerprintSpec { .. },
    p0f:                       P0fSignature       = P0fSignature { .. },
    akamai:                    AkamaiFingerprint  = AkamaiFingerprint { .. },
}

// ---- authentic wing default profile ----------------------------------------

// Constructs the authentic Wing profile. It doesn't impersonate any existing
// browser and presents a clean, recognizable systems stack fingerprint.
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

    // Canonical Wing Header Ordering (for HTTP/1.1 & JA4H)
    push_header_order(p, "host");
    push_header_order(p, "user-agent");
    push_header_order(p, "accept");
    push_header_order(p, "accept-encoding");
    push_header_order(p, "accept-language");
    push_header_order(p, "upgrade-insecure-requests");

    return p;
}

// Constructs a completely custom, blank persona for full user control.
fn custom_profile() -> ClientProfile {
    return ClientProfile {
        kind: Profile.Custom,
        ..
    };
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

// ---- profile manipulation & builder functions -------------------------------

fn push_header_order(profile: ClientProfile&, header_name: const u8[:]) {
    var entry: u8[..32] = [];
    guard entry.try_set(header_name) else { return; }
    let _ = profile.header_order.try_push(entry);
}

struct Ja4Options {
    is_quic: bool = false,
    sni:     bool = true,
}

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

struct Ja4hOptions {
    has_cookie:  bool = false,
    has_referer: bool = false,
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
    var header_names: const u8[:][>..] = [];
    if profile.user_agent.len > 0 { header_names.push("user-agent"); }
    if profile.accept.len > 0 { header_names.push("accept"); }
    if profile.accept_encoding.len > 0 { header_names.push("accept-encoding"); }
    if profile.accept_language.len > 0 { header_names.push("accept-language"); }
    if profile.upgrade_insecure_requests.len > 0 { header_names.push("upgrade-insecure-requests"); }

    for &e in profile.extra_headers.entries {
        header_names.push(entry_name(profile.extra_headers, e));
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
    set_header(profile.extra_headers, name, value);
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
fn p0f(profile: const ClientProfile&) -> u8[..256] {
    return format_p0f(profile.p0f);
}

// Configures the Akamai HTTP/2 fingerprint for this profile and synchronizes H2Settings.
fn set_akamai(profile: ClientProfile&, fp: const AkamaiFingerprint&) {
    profile.akamai = fp;
    for &s in fp.settings {
        if s.id == 1 { profile.h2.header_table_size = s.val; }
        else if s.id == 2 { profile.h2.enable_push = s.val; }
        else if s.id == 3 { profile.h2.max_concurrent_streams = s.val; }
        else if s.id == 4 { profile.h2.initial_window_size = s.val; }
        else if s.id == 5 { profile.h2.max_frame_size = s.val; }
        else if s.id == 6 { profile.h2.max_header_list_size = s.val; }
    }
}

// Formats the Akamai HTTP/2 fingerprint string for this profile.
fn akamai(profile: const ClientProfile&) -> u8[..640] {
    return akamai_fingerprint_to_string(profile.akamai);
}

// Computes the 32-character hexadecimal MD5 Akamai hash for this profile.
fn akamai_hash(profile: const ClientProfile&) -> u8[..32] {
    return akamai_fingerprint_hash(profile.akamai);
}
