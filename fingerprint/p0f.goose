// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Passive OS fingerprinting (p0f v3) TCP SYN parser and matcher (RFC 793, RFC 2018, RFC 7323).
// Provides signature parsing, packet matching, and a default TCP profile for wing.
namespace fingerprint;

import std;
import core;
import .types;
import .internal;

// ---- Authentic Wing TCP SYN Signature --------------------------------------

// Constructs the authentic Wing TCP SYN profile:
// Format string: "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0"
fn wing_p0f_signature() -> P0fSignature {
    var sig = P0fSignature {
        ip_version:    0,
        ttl:           64,
        has_ttl_minus: false,
        ip_opt_len:    0,
        mss:           -1,
        window_type:   P0fWindowType.Mss,
        window_size:   20,
        window_scale:  10,
        options:       [],
        quirks: P0fQuirks {
            df:      true,
            id_plus: true,
            ..
        },
        payload: [],
    };
    sig.options.push(P0fTcpOption.Mss);
    sig.options.push(P0fTcpOption.Sok);
    sig.options.push(P0fTcpOption.Ts);
    sig.options.push(P0fTcpOption.Nop);
    sig.options.push(P0fTcpOption.Ws);
    sig.payload.append("0");
    return sig;
}

// Constructs a blank custom p0f signature for user customization.
fn custom_p0f_signature(
    ip_version:    u8            = 0,
    ttl:           u8            = 64,
    has_ttl_minus: bool          = false,
    mss:           i32           = -1,
    window_type:   P0fWindowType = P0fWindowType.Mss,
    window_size:   i32           = 20,
    window_scale:  i16           = 10,
) -> P0fSignature {
    return P0fSignature {
        ip_version:    ip_version,
        ttl:           ttl,
        has_ttl_minus: has_ttl_minus,
        ip_opt_len:    0,
        mss:           mss,
        window_type:   window_type,
        window_size:   window_size,
        window_scale:  window_scale,
        options:       [],
        quirks:        P0fQuirks { .. },
        payload:       [],
    };
}

// ---- Signature Formatting & Parsing ----------------------------------------

// Formats a p0f signature structure into the standard 8-field p0f v3 string.
fn format_p0f(sig: const P0fSignature&) -> u8[..256] {
    var out: u8[..256] = [];

    if sig.ip_version == 4 {
        out.push('4');
    } else if sig.ip_version == 6 {
        out.push('6');
    } else {
        out.push('*');
    }
    out.push(':');

    sig.ttl.format_u32_dec(out);
    if sig.has_ttl_minus {
        out.push('-');
    }
    out.push(':');

    sig.ip_opt_len.format_u32_dec(out);
    out.push(':');

    if sig.mss == -1 {
        out.push('*');
    } else {
        sig.mss.format_i64_dec(out);
    }
    out.push(':');

    fingerprint_internal::append_p0f_window(sig, out);
    out.push(':');

    fingerprint_internal::append_p0f_options(sig.options[..], out);
    out.push(':');

    fingerprint_internal::append_p0f_quirks(sig.quirks, out);
    out.push(':');

    out.append(sig.payload[..]);
    return out;
}

// Parses an 8-field p0f v3 signature string without dynamic heap allocations.
//
// Example:
//   raw = "4:64:0:1460:mss*10,0:mss,sok,ts,nop,ws:df,id+:0"
//   returns: sig = P0fSignature { .. }, ok = true
fn parse_p0f(raw: const u8[:]) -> P0fSignature, bool {
    var dummy = P0fSignature { .. };
    guard raw.len > 0 else { return dummy, false; }

    var colons: i64[..8] = [];
    guard fingerprint_internal::parse_p0f_colons(raw, colons) else { return dummy, false; }

    let f0 = raw[..colons[0]];
    let f1 = raw[core::add_sat_i64(colons[0], 1)..colons[1]];
    let f2 = raw[core::add_sat_i64(colons[1], 1)..colons[2]];
    let f3 = raw[core::add_sat_i64(colons[2], 1)..colons[3]];
    let f4 = raw[core::add_sat_i64(colons[3], 1)..colons[4]];
    let f5 = raw[core::add_sat_i64(colons[4], 1)..colons[5]];
    let f6 = raw[core::add_sat_i64(colons[5], 1)..colons[6]];
    let f7 = raw[core::add_sat_i64(colons[6], 1)..];

    var sig = P0fSignature {
        ip_version:    0,
        ttl:           64,
        has_ttl_minus: false,
        ip_opt_len:    0,
        mss:           -1,
        window_type:   P0fWindowType.Normal,
        window_size:   0,
        window_scale:  0,
        options:       [],
        quirks:        P0fQuirks { .. },
        payload:       [],
    };

    guard fingerprint_internal::parse_p0f_header_fields(f0, f1, f2, f3, sig) else {
        return dummy, false;
    }
    guard fingerprint_internal::parse_p0f_window(f4, sig) else { return dummy, false; }
    guard fingerprint_internal::parse_p0f_options_field(f5, sig) else { return dummy, false; }
    guard fingerprint_internal::parse_p0f_quirks_field(f6, sig) else { return dummy, false; }
    guard (f7 == "0" || f7 == "+" || f7 == "*") && sig.payload.try_set(f7) else {
        return dummy, false;
    }

    return sig, true;
}

// ---- Pattern Matching ------------------------------------------------------

// Matches an observed TCP SYN signature against a target pattern signature.
// Supports wildcards ('*', '64-', '*,-1', mss/mtu multipliers).
fn match_p0f(actual: const P0fSignature&, target: const P0fSignature&) -> bool {
    guard target.ip_version == 0 || actual.ip_version == 0
        || actual.ip_version == target.ip_version else {
        return false;
    }
    guard fingerprint_internal::match_p0f_ttl(actual, target) else { return false; }
    guard actual.ip_opt_len == target.ip_opt_len else { return false; }
    guard target.mss == -1 || actual.mss == target.mss else { return false; }
    guard target.window_scale == -1 || actual.window_scale == target.window_scale else { return false; }
    guard fingerprint_internal::match_p0f_window(actual, target) else { return false; }
    guard actual.options[..] == target.options[..] else { return false; }
    guard actual.quirks == target.quirks else { return false; }
    guard target.payload[..] == "*" || actual.payload[..] == target.payload[..] else { return false; }
    return true;
}

// ---- Builder Helpers & Socket Option Extraction ----------------------------

// Appends a TCP option to the signature, returning `false` if at capacity (16 options).
fn push_option(sig: P0fSignature&, opt: P0fTcpOption) -> bool {
    return sig.options.try_push(opt);
}

// Sets a quirk by token name, returning `false` if `quirk_name` is unknown.
fn set_quirk(sig: P0fSignature&, quirk_name: const u8[:], enabled: bool) -> bool {
    return fingerprint_internal::apply_quirk(sig.quirks, quirk_name, enabled);
}

// Checks whether a quirk by token name is set.
fn has_quirk(sig: const P0fSignature&, quirk_name: const u8[:]) -> bool {
    let idx, ok = fingerprint_internal::quirk_index(quirk_name);
    guard ok else { return false; }
    let flags = fingerprint_internal::quirks_flags(sig.quirks);
    return flags[idx];
}

// Converts a p0f signature into concrete OS socket options (IP_TTL, IP_DONTFRAGMENT, SO_RCVBUF).
fn to_socket_opts(sig: const P0fSignature&, base_mss: i32 = 1460) -> P0fSocketOpts {
    var opts = P0fSocketOpts {
        ttl:                 sig.ttl,
        dont_fragment:       sig.quirks.df,
        receive_buffer_size: 262144,
    };

    match sig.window_type {
        Normal => {
            if sig.window_size > 0 {
                opts.receive_buffer_size = sig.window_size;
            }
        },
        Mss => {
            let mss = (if sig.mss > 0 { sig.mss } else { max(base_mss, 0) }) as u64;
            let prod = core::mul_sat_u64(mss, max(sig.window_size, 0) as u64);
            opts.receive_buffer_size = min(prod, 2147483647) as i32;
        },
        Mtu => {
            let hdr_len: u64 = if sig.ip_version == 6 { 60 } else { 40 };
            let mtu = core::add_sat_u64(max(base_mss, 0) as u64, hdr_len);
            let prod = core::mul_sat_u64(mtu, max(sig.window_size, 0) as u64);
            opts.receive_buffer_size = min(prod, 2147483647) as i32;
        },
        _ => {},
    }

    return opts;
}
