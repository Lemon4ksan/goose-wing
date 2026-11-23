// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Shared internal JOSE, JWE, key validation, JSON formatting, and Digest lexer helpers.
namespace auth_internal;

import std;
import json;
import core;
import rfc.http;
import .types;

// ---- Shared JSON Key Tracking & Algorithm Metadata -----------------------

struct SeenHeaderKey {
    name: u8[..64] = [],
}

struct SeenCustomKey {
    name: u8[..128] = [],
}

inline fn is_header_key_present(name: const u8[:], seen: const SeenHeaderKey[:]) -> bool {
    for &o in seen {
        if o.name[..] == name { return true; }
    }
    return false;
}

inline fn seen_custom_keys_contains(key: const u8[:], seen: const SeenCustomKey[..64]) -> bool {
    for &sc in seen {
        if sc.name[..] == key { return true; }
    }
    return false;
}

fn jwt_alg_to_string(alg: auth::JwtAlg) -> const u8[:] {
    return match alg {
        Unspecified => "",
        None => "none",
        HS256 => "HS256",
        HS384 => "HS384",
        HS512 => "HS512",
        EdDSA => "EdDSA",
        ES256 => "ES256",
        RS256 => "RS256",
        PS256 => "PS256",
        Unknown => "unknown",
    };
}

// RFC 7518 Section 3.2: HMAC with SHA-2 Functions - key must be at least hash output length.
inline fn hmac_min_key_len(alg: auth::JwtAlg) -> i64 {
    return match alg {
        HS256 => rfc::HMAC_SHA256_MAC_LEN,
        HS384 => rfc::HMAC_SHA384_MAC_LEN,
        HS512 => rfc::HMAC_SHA512_MAC_LEN,
        _ => 0,
    };
}

// ---- JWE & ConcatKDF Internal Helpers (RFC 7516 / RFC 7518 §4.6.2) -------

inline fn append_be32_prefixed_slice<B>(buf: B&, s: const u8[:]) -> bool {
    guard s.len >= 0 && s.len <= 0x7FFFFFFF else { return false; }
    var len_be: u8[4] = [0; 4];
    core::write_be_u32_at(len_be[..], 0, (s.len & 0x7FFFFFFF) as u32);
    return buf.try_append(len_be[..]) && buf.try_append(s);
}

inline fn build_concat_kdf_input<B>(
    buf:      B&,
    z:        const u8[32]&,
    alg_id:   const u8[:],
    apu:      const u8[:],
    apv:      const u8[:],
    key_bits: u32,
) -> bool {
    var round_be: u8[4] = [0, 0, 0, 1];
    var bits_be:  u8[4] = [0; 4];
    core::write_be_u32_at(bits_be[..], 0, key_bits);
    return buf.try_append(round_be[..]) &&
        buf.try_append(z[..]) &&
        append_be32_prefixed_slice(buf, alg_id) &&
        append_be32_prefixed_slice(buf, apu) &&
        append_be32_prefixed_slice(buf, apv) &&
        buf.try_append(bits_be[..]);
}

inline fn read_jwe_expected_str_field(
    reader:   json::Reader&,
    expected: const u8[:],
    has_flag: bool&,
    had_err:  bool&,
) {
    var val_buf: u8[..32] = [];
    if json::peek(reader) == '"' && core::read_json_string_into(reader, val_buf) && val_buf[..] == expected {
        has_flag = true;
    } else {
        json::skip(reader);
        had_err = true;
    }
}

inline fn read_jwe_protected_member(
    key:       const u8[:],
    reader:    json::Reader&,
    seen_keys: SeenHeaderKey[..16]&,
    has_alg:   bool&,
    has_enc:   bool&,
    had_err:   bool&,
) {
    if key.contains('\\') || is_header_key_present(key, seen_keys[..]) {
        had_err = true;
        json::skip(reader);
        return;
    }
    var seen_item = SeenHeaderKey { .. };
    if !seen_item.name.try_set(key) || !seen_keys.try_push(seen_item) {
        had_err = true;
        json::skip(reader);
        return;
    }
    if key == "alg" {
        read_jwe_expected_str_field(reader, "dir", has_alg, had_err);
        return;
    }
    if key == "enc" {
        read_jwe_expected_str_field(reader, "A256GCM", has_enc, had_err);
        return;
    }
    if key == "crit" || key == "zip" {
        had_err = true;
        json::skip(reader);
        return;
    }
    json::skip(reader);
}

// Validates RFC 7516 §4 / §5.2 JWE Protected Header for direct A256GCM encryption.
fn validate_jwe_dir_a256gcm_header(protected_b64: const u8[:]) -> bool {
    guard protected_b64.len > 0 && protected_b64.len <= auth::MAX_JWT_HEADER_PART_LEN else { return false; }
    guard protected_b64.index_of_byte('=') == -1 else { return false; }
    var hdr_json: u8[..2048] = [];
    guard core::base64url_decode(protected_b64, hdr_json) else { return false; }
    guard hdr_json.len > 0 && hdr_json[..].validate_utf8() else { return false; }

    var reader = json::reader(hdr_json[..]);
    guard json::peek(reader) == '{' else { return false; }
    var seen_keys: SeenHeaderKey[..16] = [];
    var has_alg = false;
    var has_enc = false;
    var had_err = false;
    json::each_member(reader) { key =>
        read_jwe_protected_member(key, reader, seen_keys, has_alg, has_enc, had_err);
    };
    return json::finish(reader) && !had_err && has_alg && has_enc;
}

struct JweParts {
    d1: i64 = -1,
    d2: i64 = -1,
    d3: i64 = -1,
    d4: i64 = -1,
}

// Splits an RFC 7516 JWE Compact Serialization into its 4 dot positions (5 segments).
//
// Example:
//   token = "hdr..iv.ct.tag"
//   returns: JweParts { d1: 3, d2: 4, d3: 7, d4: 10 }, ok = true
fn split_jwe_compact_parts(token: const u8[:]) -> JweParts, bool {
    var parts = JweParts { .. };
    guard token.len > 0 && token.len <= auth::MAX_JWT_TOKEN_LEN else { return parts, false; }
    for i in token.len {
        if token[i] == '.' {
            if parts.d1 == -1 {
                parts.d1 = i;
            } else if parts.d2 == -1 {
                parts.d2 = i;
            } else if parts.d3 == -1 {
                parts.d3 = i;
            } else if parts.d4 == -1 {
                parts.d4 = i;
            } else {
                return JweParts { .. }, false;
            }
        }
    }
    let valid = parts.d1 > 0 && parts.d2 > parts.d1 && parts.d3 > parts.d2 &&
        parts.d4 > parts.d3 && parts.d4 < core::sub_sat_i64(token.len, 1);
    guard valid else { return JweParts { .. }, false; }
    return parts, true;
}

// ---- Digest Internal Helpers (RFC 7616) ----------------------------------

inline fn is_valid_quoted_digest_byte(b: u8) -> bool {
    return core::is_ascii_printable(b) || b >= 0x80;
}

// Consumes one quoted-pair or unescaped character at `pos` into `out`.
//
// Example:
//   s = "\"\\a\"", pos = 1
//   returns: ok = true, pos = 3, out = "a"
inline fn try_consume_quoted_char<B>(s: const u8[:], pos: i64&, out: B&) -> bool {
    let b = s[pos];
    let next_pos = core::add_sat_i64(pos, 1);
    if b == '\\' && next_pos < s.len {
        let esc = s[next_pos];
        guard is_valid_quoted_digest_byte(esc) && out.try_push(esc) else { return false; }
        pos = core::add_sat_i64(next_pos, 1);
        return true;
    }
    guard b != '\\' && is_valid_quoted_digest_byte(b) && out.try_push(b) else { return false; }
    pos = next_pos;
    return true;
}

inline fn is_digest_token_delim(b: u8) -> bool {
    return b == ' ' || b == '\t' || b == ',' || b == '\r' || b == '\n';
}

// Scans an unquoted digest token length up to whitespace, comma, or newline (RFC 7616 §3.3).
//
// Example:
//   s = "token123, next=val"
//   returns: 8 (length of "token123")
inline fn scan_digest_token_len(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    while n < s.len && !is_digest_token_delim(s[n]) && core::is_tchar(s[n]) {
        n = core::add_sat_i64(n, 1);
    }
    return n;
}

// Scans the byte length of a single qop token up to delimiter (RFC 7616 Section 3.3).
//
// Example:
//   s = "auth-int, auth"
//   returns: 8
inline fn scan_qop_token_len(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    while n < s.len && core::is_tchar(s[n]) {
        n = core::add_sat_i64(n, 1);
    }
    return n;
}

const DIGEST_STACK_FAST_CAP: i64 = 1024;

inline fn append_digest_pair<B>(out: B&, a: const u8[:], b: const u8[:]) {
    out.append(a);
    out.push(':');
    out.append(b);
}

inline fn append_digest_triple<B>(out: B&, a: const u8[:], b: const u8[:], c: const u8[:]) {
    out.append(a);
    out.push(':');
    out.append(b);
    out.push(':');
    out.append(c);
}

inline fn append_digest_kd_parts<B>(
    out:        B&,
    ha1_hex:    const u8[:],
    nonce:      const u8[:],
    nc_str:     const u8[:],
    cnonce:     const u8[:],
    active_qop: const u8[:],
    ha2_hex:    const u8[:],
) {
    out.append(ha1_hex);
    out.push(':');
    out.append(nonce);
    out.push(':');
    if active_qop.len > 0 {
        out.append(nc_str);
        out.push(':');
        out.append(cnonce);
        out.push(':');
        out.append(active_qop);
        out.push(':');
    }
    out.append(ha2_hex);
}

// ---- Shared EC / RSA / Key Validators -----------------------------------

inline fn is_valid_jwk_ec_p256_coords(x: const u8[:], y: const u8[:]) -> bool {
    guard x.len == 32 && y.len == 32 else { return false; }
    var pub_pt: u8[..65] = [];
    pub_pt.push(0x04);
    pub_pt.append(x);
    pub_pt.append(y);
    let _, ok_pt = core::decode_p256_public_key(pub_pt[..]);
    return ok_pt;
}

inline fn is_canonical_jwk_rsa_params(n_be: const u8[:], e_be: const u8[:]) -> bool {
    guard n_be.len >= 256 && n_be.len <= 512 && e_be.len >= 1 && e_be.len <= 8 else { return false; }
    let n_last = core::sub_sat_i64(n_be.len, 1);
    guard (n_be[0] & 0x80) != 0 && (n_be[n_last] & 1) == 1 else { return false; }
    return e_be[0] != 0 && core::is_valid_rsa_public_exponent(e_be, n_be);
}

inline fn has_nonzero_byte_32(buf: const u8[32]&) -> bool {
    var acc: u8 = 0;
    for b in buf { acc = acc | b; }
    return acc != 0;
}

// ---- Shared JSON Member Formatting Helpers -------------------------------

inline fn append_json_str_member<B>(
    key:   const u8[:],
    val:   const u8[:],
    first: bool&,
    out:   B&,
) -> bool {
    guard val.len > 0 else { return true; }
    if !first { guard out.try_push(',' as u8) else { return false; } }
    first = false;
    return core::try_format_json_key(out, key) && core::try_format_json_string(out, val);
}

inline fn append_json_int_member<B>(
    key:   const u8[:],
    val:   i64,
    first: bool&,
    out:   B&,
) -> bool {
    guard val >= 0 else { return true; }
    if !first { guard out.try_push(',' as u8) else { return false; } }
    first = false;
    return core::try_format_json_key(out, key) && core::try_format_i64_dec(val, out);
}

inline fn serialize_audiences_member<B>(
    claims: const auth::JwtClaims&,
    first:  bool&,
    out:    B&,
) -> bool {
    if claims.audiences.len > 1 {
        if !first { guard out.try_push(',' as u8) else { return false; } }
        first = false;
        guard out.try_append("\"aud\":[") else { return false; }
        for i in claims.audiences.len {
            if i > 0 { guard out.try_push(',' as u8) else { return false; } }
            guard core::try_format_json_string(out, claims.audiences[i][..]) else { return false; }
        }
        return out.try_push(']' as u8);
    }
    if claims.audiences.len == 1 || claims.aud.len > 0 {
        let one_aud = if claims.audiences.len == 1 { claims.audiences[0][..] } else { claims.aud[..] };
        return append_json_str_member("aud", one_aud, first, out);
    }
    return true;
}

inline fn serialize_custom_claim<B>(
    c:     const auth::JwtClaimItem&,
    first: bool&,
    out:   B&,
) -> bool {
    if !first { guard out.try_push(',' as u8) else { return false; } }
    first = false;
    guard core::try_format_json_key(out, c.key[..]) else { return false; }
    if c.is_num {
        return core::try_format_i64_dec(c.val_num, out);
    }
    if c.is_bool {
        return out.try_append(if c.val_bool { "true" } else { "false" });
    }
    return core::try_format_json_string(out, c.val_str[..]);
}

// Appends a validated, non-standard, non-duplicate `crit` parameter name to `list` (RFC 7515 §4.1.11).
inline fn append_unique_crit_param(list: auth::CritParam[..8]&, name: const u8[:]) -> bool {
    guard name.len > 0 && !rfc::is_standard_jws_header_param(name) else { return false; }
    for &cp in list {
        guard cp.name[..] != name else { return false; }
    }
    var item = auth::CritParam { .. };
    return item.name.try_set(name) && list.try_push(item);
}
