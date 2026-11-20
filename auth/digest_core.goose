// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP Digest parameter parsing and RFC 7616 cryptographic hash helpers.
namespace auth;

import std;
import core from "..";
import rfc.http;
import .types;
import .internal;

// Extracts an unquoted Digest parameter key up to OWS or '=' (RFC 7616 Section 3.3).
//
// Example:
//   raw = "realm=\"api\", nonce=\"xyz\"", idx = 0
//   returns: "realm", ok = true, idx = 5 (points to '=')
fn parse_digest_param_key(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    let start = idx;
    while idx < raw.len && core::is_tchar(raw[idx]) {
        idx = core::add_sat_i64(idx, 1);
    }
    guard idx > start else { return "", false; }
    return raw[start..idx], true;
}

// Parses an RFC 9110 quoted-string starting at s[0] == '"' into `out`, unescaping quoted-pairs.
//
// Example:
//   s = "\"a\\\"b\", next=1"
//   returns: consumed = 6, ok = true, out = "a\"b"
fn parse_quoted_param<B>(s: const u8[:], out: B&) -> i64, bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard s.len >= 2 && s[0] == '"' else { return 0, false; }

    out.clear();
    var pos: i64 = 1;
    while pos < s.len {
        if s[pos] == '"' {
            committed = true;
            return core::add_sat_i64(pos, 1), true;
        }
        guard auth_internal::try_consume_quoted_char(s, pos, out) else { return 0, false; }
    }
    return 0, false;
}

// Parses an RFC 7616 Digest parameter value (`=...`) starting from optional OWS before '=' into `out`.
//
// Example:
//   raw = "realm=\"api\"", idx = 5
//   returns: true, idx = 11, out = "api"
fn parse_digest_param_val<B>(raw: const u8[:], idx: i64&, out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    while idx < raw.len && core::is_lws(raw[idx]) {
        idx = core::add_sat_i64(idx, 1);
    }
    guard idx < raw.len && raw[idx] == '=' else { return false; }
    idx = core::add_sat_i64(idx, 1);
    while idx < raw.len && core::is_lws(raw[idx]) {
        idx = core::add_sat_i64(idx, 1);
    }
    guard idx < raw.len else { return false; }

    if raw[idx] == '"' {
        let consumed, ok_q = parse_quoted_param(raw[idx..], out);
        guard ok_q else { return false; }
        idx = core::add_sat_i64(idx, consumed);
        committed = true;
        return true;
    }
    let tok_len = auth_internal::scan_digest_token_len(raw[idx..]);
    guard tok_len > 0 else { return false; }
    let end = core::add_sat_i64(idx, tok_len);
    guard out.try_set(raw[idx..end]) else { return false; }
    idx = end;
    committed = true;
    return true;
}

// RFC 7616 Section 3.4: Computes lowercase hex digest for MD5, SHA-256, or SHA-512-256 (incl. -sess).
fn digest_hash_hex(algorithm: const u8[:], data: const u8[:]) -> u8[..64] {
    var out: u8[..64] = [];
    if algorithm.eq_ascii_fold(rfc::DIGEST_ALGO_MD5) || algorithm.eq_ascii_fold(rfc::DIGEST_ALGO_MD5_SESS) {
        var d = core::md5(data);
        defer core::secure_zeroize_16(d);
        for b in d { b.format_u8_hex(out, false); }
        return out;
    }
    if algorithm.eq_ascii_fold(rfc::DIGEST_ALGO_SHA256) || algorithm.eq_ascii_fold(rfc::DIGEST_ALGO_SHA256_SESS) {
        var d = core::sha256(data);
        defer core::secure_zeroize_32(d);
        for b in d { b.format_u8_hex(out, false); }
        return out;
    }
    if algorithm.eq_ascii_fold(rfc::DIGEST_ALGO_SHA512_256) ||
        algorithm.eq_ascii_fold(rfc::DIGEST_ALGO_SHA512_256_SESS) {
        // RFC 7616 Section 3.9.2: SHA-512-256 Digest uses first 256 bits of SHA-512.
        var d = core::sha512(data);
        defer core::secure_zeroize_64(d);
        for i in 32 { d[i].format_u8_hex(out, false); }
        return out;
    }
    return out;
}

// RFC 7616 Section 3.4.2: A1 calculation for MD5/SHA-256/SHA-512-256 and -sess variants.
fn calculate_digest_ha1(
    algo:     const u8[:],
    username: const u8[:],
    realm:    const u8[:],
    password: const u8[:],
    nonce:    const u8[:],
    cnonce:   const u8[:],
) -> u8[..64] {
    guard username.len > 0 && realm.len > 0 else { return []; }
    var a1: u8[>..] = [];
    defer core::secure_zeroize_slice(a1[..]);
    a1.append(username);
    a1.push(':');
    a1.append(realm);
    a1.push(':');
    a1.append(password);

    var ha1_base = digest_hash_hex(algo, a1[..]);
    defer core::secure_zeroize_slice(ha1_base[..]);
    guard ha1_base.len > 0 else { return []; }
    if !rfc::is_sess_digest_algo(algo) {
        return ha1_base;
    }

    guard nonce.len > 0 && cnonce.len > 0 else { return []; }
    var a1_sess: u8[>..] = [];
    defer core::secure_zeroize_slice(a1_sess[..]);
    a1_sess.append(ha1_base[..]);
    a1_sess.push(':');
    a1_sess.append(nonce);
    a1_sess.push(':');
    a1_sess.append(cnonce);
    return digest_hash_hex(algo, a1_sess[..]);
}

// RFC 7616 Section 3.4.3: A2 calculation for standard and "auth-int" qop modes.
fn calculate_digest_ha2(
    algo:        const u8[:],
    method:      const u8[:],
    uri:         const u8[:],
    is_auth_int: bool,
    body:        const u8[:],
) -> u8[..64] {
    guard method.len > 0 && uri.len > 0 else { return []; }
    var a2: u8[>..] = [];
    defer core::secure_zeroize_slice(a2[..]);
    a2.append(method);
    a2.push(':');
    a2.append(uri);
    if is_auth_int {
        var body_hex = digest_hash_hex(algo, body);
        guard body_hex.len > 0 else { return []; }
        a2.push(':');
        a2.append(body_hex[..]);
    }
    return digest_hash_hex(algo, a2[..]);
}

// RFC 7616 Section 3.4.1: Request-digest KD computation with optional qop/nc/cnonce binding.
fn calculate_digest_response(
    algo:       const u8[:],
    ha1_hex:    const u8[:],
    nonce:      const u8[:],
    nc_str:     const u8[:],
    cnonce:     const u8[:],
    active_qop: const u8[:],
    ha2_hex:    const u8[:],
) -> u8[..64] {
    guard ha1_hex.len > 0 && nonce.len > 0 && ha2_hex.len > 0 else { return []; }
    var kd: u8[>..] = [];
    defer core::secure_zeroize_slice(kd[..]);
    kd.append(ha1_hex);
    kd.push(':');
    kd.append(nonce);
    kd.push(':');
    if active_qop.len > 0 {
        guard nc_str.len > 0 && cnonce.len > 0 else { return []; }
        kd.append(nc_str);
        kd.push(':');
        kd.append(cnonce);
        kd.push(':');
        kd.append(active_qop);
        kd.push(':');
    }
    kd.append(ha2_hex);
    return digest_hash_hex(algo, kd[..]);
}

// Appends a digest URI without backslash escaping, rejecting CTLs, quotes, and backslashes (RFC 7616 §3.4).
fn append_digest_uri<B>(out: B&, uri: const u8[:]) -> bool {
    guard uri.len > 0 else { return false; }
    for b in uri {
        guard b != '\r' && b != '\n' && b != '\0' && b != '"' && b != '\\' else { return false; }
    }
    return out.try_append(uri);
}

// RFC 7616 Section 3.4.4: Computes H(username ":" realm) when `userhash=true` is negotiated.
fn resolve_userhash(username: const u8[:], realm: const u8[:], algo: const u8[:]) -> u8[..64] {
    guard username.len > 0 && realm.len > 0 else { return []; }
    var buf: u8[>..] = [];
    defer core::secure_zeroize_slice(buf[..]);
    buf.append(username);
    buf.push(':');
    buf.append(realm);
    return digest_hash_hex(algo, buf[..]);
}

// Checks whether a comma-separated RFC 7616 `qop` list contains `target` and validates all list tokens.
fn qop_list_has_token(raw_qop: const u8[:], target: const u8[:]) -> bool {
    guard target.len > 0 else { return false; }
    var idx:   i64  = 0;
    var found: bool = false;
    while idx < raw_qop.len {
        let rem = raw_qop[idx..].trim_start_bytes(" \t,\"");
        guard rem.len > 0 else { break; }
        let tok_len = auth_internal::scan_qop_token_len(rem);
        guard tok_len > 0 else { return false; }
        let tok = rem[..tok_len];
        let after_tok = rem[tok_len..].trim_start_bytes(" \t\"");
        guard after_tok.len == 0 || after_tok[0] == ',' else { return false; }
        if tok.eq_ascii_fold(target) {
            found = true;
        }
        idx = core::sub_sat_i64(raw_qop.len, after_tok.len);
        if idx < raw_qop.len && raw_qop[idx] == ',' {
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return found;
}
