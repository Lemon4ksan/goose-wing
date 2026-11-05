// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wing Profile and Persona Engine.
// Enforces Wing's authentic zero-heap identity by default, with complete user-level
// control over headers, meta-headers, TLS parameters, and JA4 fingerprint generation.
namespace wing;

import std;
import client.profile;
import fingerprint.ja4;
import fingerprint.p0f;
import fingerprint.akamai;

// Profile kind.

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
    qpack_max_table_capacity: u64 = 4096,
    max_field_section_size:   u64 = 65536,
    qpack_blocked_streams:    u64 = 16,
    enable_connect_protocol:  u64 = 1,
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

// Backward-compatible alias for existing callers
type BrowserProfile = ClientProfile;

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

    // 1. Authentic Wing User-Agent
    p.user_agent.append("Wing/1.0 (Goose Zero-Heap Systems Engine) NetStack/7.0");

    // 2. Standard content negotiation (advertising native RFC 8878 Zstandard)
    p.accept.append("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
    p.accept_encoding.append("zstd, gzip, br");
    p.accept_language.append("en-US,en;q=0.9");
    p.upgrade_insecure_requests.append("1");

    // 3. Wing TLS Spec: Pure modern high-security suites (clean, deterministic)
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

    // 4. Canonical Wing Header Ordering (for HTTP/1.1 & JA4H)
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

fn push_header_order(profile: BrowserProfile&, header_name: const u8[:]) {
    guard header_name.len <= 32 && profile.header_order.len < profile.header_order.cap else { return; }
    var entry: u8[..32] = [];
    entry.append(header_name);
    profile.header_order.push(entry);
}

struct Ja4Options {
    is_quic: bool = false,
    sni:     bool = true,
}

// Computes the FoxIO JA4 TLS fingerprint for this profile.
fn ja4(profile: const BrowserProfile&, opts: Ja4Options = Ja4Options { .. }) -> u8[..64] {
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
    profile:       const BrowserProfile&,
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
fn set_header(profile: BrowserProfile&, name: const u8[:], value: const u8[:]) {
    if eq_ascii_fold(name, "user-agent") {
        set_user_agent(profile, value);
        return;
    }
    if eq_ascii_fold(name, "accept") {
        set_accept(profile, value);
        return;
    }
    if eq_ascii_fold(name, "accept-encoding") {
        set_accept_encoding(profile, value);
        return;
    }
    if eq_ascii_fold(name, "accept-language") {
        set_accept_language(profile, value);
        return;
    }
    if eq_ascii_fold(name, "upgrade-insecure-requests") {
        profile.upgrade_insecure_requests.clear();
        profile.upgrade_insecure_requests.append(value);
        return;
    }
    set_header(profile.extra_headers, name, value);
}

// Sets a custom User-Agent in the profile.
fn set_user_agent(profile: BrowserProfile&, ua: const u8[:]) {
    profile.user_agent.clear();
    profile.user_agent.append(ua);
}

// Sets Accept header in the profile.
fn set_accept(profile: BrowserProfile&, accept_str: const u8[:]) {
    profile.accept.clear();
    profile.accept.append(accept_str);
}

// Sets Accept-Encoding header in the profile.
fn set_accept_encoding(profile: BrowserProfile&, enc: const u8[:]) {
    profile.accept_encoding.clear();
    profile.accept_encoding.append(enc);
}

// Sets Accept-Language header in the profile.
fn set_accept_language(profile: BrowserProfile&, lang: const u8[:]) {
    profile.accept_language.clear();
    profile.accept_language.append(lang);
}

// Configures the p0f TCP SYN signature for this profile.
fn set_p0f(profile: BrowserProfile&, sig: const P0fSignature&) {
    profile.p0f = sig;
}

// Computes the p0f v3 format string for this profile.
fn p0f(profile: const BrowserProfile&) -> u8[..128] {
    return format_p0f(profile.p0f);
}

// Configures the Akamai HTTP/2 fingerprint for this profile.
fn set_akamai(profile: BrowserProfile&, fp: const AkamaiFingerprint&) {
    profile.akamai = fp;
}

// Formats the Akamai HTTP/2 fingerprint string for this profile.
fn akamai(profile: const BrowserProfile&) -> u8[..256] {
    return akamai_fingerprint_to_string(profile.akamai);
}

// Computes the 32-character hexadecimal MD5 Akamai hash for this profile.
fn akamai_hash(profile: const BrowserProfile&) -> u8[..32] {
    return akamai_fingerprint_hash(profile.akamai);
}
