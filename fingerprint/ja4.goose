// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// FoxIO JA4+ network fingerprinting algorithms: JA4 (TLS) and JA4H (HTTP).
// Conforms to FoxIO JA4 specification with zero dynamic allocations.
namespace fingerprint;

import std;
import core from "..";
import .types;
import .internal;

// ---- JA4 TLS Client Fingerprint --------------------------------------------

// Computes the FoxIO JA4 TLS client fingerprint into `out` in format:
// {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
// E.g.: "t13d1516h2_8daaf6152771_e5627efa2ab1"
fn compute_ja4<B>(
    ciphers:            const u16[:],
    extensions:         const u16[:],
    supported_versions: const u16[:],
    sni:                bool,
    alpn_protocol:      const u8[:],
    sig_algorithms:     const u16[:],
    is_quic:            bool,
    out:                B&,
) {
    out.clear();
    out.push(if is_quic { 'q' } else { 't' });
    out.append(fingerprint_internal::ja4_version_string(supported_versions));
    out.push(if sni { 'd' } else { 'i' });

    var filtered_ciphers: u16[>..] = [];
    fingerprint_internal::filter_grease_u16(ciphers, filtered_ciphers);
    fingerprint_internal::append_two_digits(filtered_ciphers.len, out);

    var filtered_exts: u16[>..] = [];
    fingerprint_internal::filter_grease_u16(extensions, filtered_exts);
    fingerprint_internal::append_two_digits(filtered_exts.len, out);

    fingerprint_internal::ja4_alpn_string(alpn_protocol, out);
    out.push('_');
    fingerprint_internal::append_ja4_ciphers_hash(filtered_ciphers, out);
    out.push('_');
    fingerprint_internal::append_ja4_extensions_hash(filtered_exts[..], sig_algorithms, out);
}

// Computes the FoxIO JA4 TLS client fingerprint returning a fixed-capacity buffer.
fn compute_ja4(
    ciphers:            const u16[:],
    extensions:         const u16[:],
    supported_versions: const u16[:],
    sni:                bool         = true,
    alpn_protocol:      const u8[:]  = "h2",
    sig_algorithms:     const u16[:] = [],
    is_quic:            bool         = false,
) -> u8[..64] {
    var out: u8[..64] = [];
    compute_ja4(ciphers, extensions, supported_versions, sni, alpn_protocol, sig_algorithms, is_quic, out);
    return out;
}

// ---- JA4H HTTP Client Fingerprint ------------------------------------------

// Computes the FoxIO JA4H HTTP client fingerprint into `out` in format:
// {method}{version}{cookie}{referer}{header_count}{lang}_{headers_hash}_{cookie_names}_{cookie_values}
// E.g.: "ge20cn04enus_1c8f3b0e29d1_000000000000_000000000000"
fn compute_ja4h<B>(
    method:          const u8[:],
    proto:           const u8[:],
    header_names:    const u8[:][:],
    flags:           Ja4hFlags,
    accept_language: const u8[:],
    cookie_names:    const u8[:][:],
    cookie_values:   const u8[:][:],
    out:             B&,
) {
    out.clear();
    if method.len >= 2 {
        out.push(core::to_lower_ascii_byte(method[0]));
        out.push(core::to_lower_ascii_byte(method[1]));
    } else {
        out.append("00");
    }

    out.append(fingerprint_internal::ja4h_proto_string(proto));

    let filtered_headers, resolved = fingerprint_internal::filter_ja4h_headers(
        header_names,
        flags,
        cookie_names.len > 0,
    );

    out.push(if resolved.has_cookie { 'c' } else { 'n' });
    out.push(if resolved.has_referer { 'r' } else { 'n' });
    fingerprint_internal::append_two_digits(filtered_headers.len, out);
    fingerprint_internal::append_ja4h_language(accept_language, out);
    out.push('_');
    fingerprint_internal::append_ja4h_headers_hash(filtered_headers[..], out);
    out.push('_');
    fingerprint_internal::append_ja4h_cookies_hash(cookie_names, cookie_values, out);
}

// Computes the FoxIO JA4H HTTP client fingerprint returning a fixed-capacity buffer.
fn compute_ja4h(
    method:          const u8[:],
    proto:           const u8[:],
    header_names:    const u8[:][:],
    flags:           Ja4hFlags      = Ja4hFlags { .. },
    accept_language: const u8[:]    = "",
    cookie_names:    const u8[:][:] = [],
    cookie_values:   const u8[:][:] = [],
) -> u8[..64] {
    var out: u8[..64] = [];
    compute_ja4h(
        method,
        proto,
        header_names,
        flags,
        accept_language,
        cookie_names,
        cookie_values,
        out,
    );
    return out;
}
