// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers, constants, and state tables shared across the auth package.
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

// ---- ACME Internal Validators (RFC 8555 §8.1 / §8.3) ---------------------

// RFC 8555 Section 8.3: HTTP Challenge - token must have at least 128 bits of entropy (22 base64url chars)
const ACME_MIN_TOKEN_LEN: i64 = 22;
const ACME_MAX_TOKEN_LEN: i64 = 64;
// RFC 8555 Section 8.1: Key Authorizations - SHA-256 JWK thumbprint is 43 base64url characters
const ACME_THUMBPRINT_LEN: i64 = 43;

inline fn is_acme_base64url_chars(s: const u8[:]) -> bool {
    for b in s {
        guard core::is_ascii_alphanumeric(b) || b == '-' || b == '_' else { return false; }
    }
    return true;
}

inline fn is_valid_acme_thumbprint(thumbprint_b64url: const u8[:]) -> bool {
    return thumbprint_b64url.len == ACME_THUMBPRINT_LEN && is_acme_base64url_chars(thumbprint_b64url);
}

inline fn is_valid_acme_challenge_slot(ch: const auth::AcmeChallenge&) -> bool {
    let tok_len = ch.token.len;
    guard tok_len >= ACME_MIN_TOKEN_LEN && tok_len <= ACME_MAX_TOKEN_LEN else { return false; }
    guard is_acme_base64url_chars(ch.token[..]) else { return false; }
    let thumb_idx = core::add_sat_i64(tok_len, 1);
    guard ch.key_auth.len > thumb_idx else { return false; }
    guard ch.key_auth[..tok_len] == ch.token[..] && ch.key_auth[tok_len] == '.' else { return false; }
    return is_valid_acme_thumbprint(ch.key_auth[thumb_idx..]);
}

// ---- Device Grant Internal Parsers (RFC 8628 §3.2) -----------------------

// Reads a required non-empty JSON string field into `dst`.
//
// Example:
//   reader at "\"WDJB-MJHT\""
//   sets: dst = "WDJB-MJHT", had_err = false
inline fn read_required_oauth_str<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
        return;
    }
    if !core::read_json_string_into(reader, dst) || dst.len == 0 {
        had_err = true;
    }
}

// Reads an optional nullable JSON string field into `dst`.
//
// Example:
//   reader at "\"https://ex.com?code=1\""
//   sets: dst = "https://ex.com?code=1", had_err = false
inline fn read_nullable_oauth_str<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    let p = json::peek(reader);
    if p == 'n' {
        json::skip(reader);
    } else if p != '"' || !core::read_json_string_into(reader, dst) {
        had_err = true;
    }
}

// Reads a required positive JSON integer field into `dst`.
//
// Example:
//   reader at "1800"
//   sets: dst = 1800, had_err = false
inline fn read_positive_oauth_int(reader: json::Reader&, dst: i64&, had_err: bool&) {
    let p = json::peek(reader);
    if core::is_ascii_digit(p) {
        dst = json::read_int(reader);
        if dst <= 0 { had_err = true; }
    } else {
        json::skip(reader);
        had_err = true;
    }
}

inline fn is_valid_device_verification_uri(uri: const u8[:]) -> bool {
    let parsed, err = core::parse_url(uri);
    guard err == core::UrlParseError.None && parsed.hostname().len > 0 else { return false; }
    let scheme = parsed.scheme();
    return scheme.eq_ascii_fold("https") || scheme.eq_ascii_fold("http");
}

inline fn mark_device_auth_key_seen(seen_mask: u32&, bit: u32, had_err: bool&) {
    if (seen_mask & bit) != 0 {
        had_err = true;
    }
    seen_mask = seen_mask | bit;
}

// Parses a single field of an RFC 8628 §3.2 Device Authorization Response JSON object.
//
// Example:
//   key = "user_code", reader at "\"WDJB-MJHT\""
//   sets: resp.user_code = "WDJB-MJHT", had_err = false
fn parse_device_auth_field(
    key:       const u8[:],
    reader:    json::Reader&,
    resp:      auth::DeviceAuthResponse&,
    seen_mask: u32&,
    had_err:   bool&,
) {
    if key.contains('\\') {
        had_err = true;
        json::skip(reader);
        return;
    }
    if key == "device_code" {
        mark_device_auth_key_seen(seen_mask, 1, had_err);
        read_required_oauth_str(reader, resp.device_code, had_err);
        return;
    }
    if key == "user_code" {
        mark_device_auth_key_seen(seen_mask, 2, had_err);
        read_required_oauth_str(reader, resp.user_code, had_err);
        return;
    }
    if key == "verification_uri" || key == "verification_url" {
        mark_device_auth_key_seen(seen_mask, 4, had_err);
        read_required_oauth_str(reader, resp.verification_uri, had_err);
        return;
    }
    if key == "verification_uri_complete" {
        mark_device_auth_key_seen(seen_mask, 8, had_err);
        read_nullable_oauth_str(reader, resp.verification_uri_complete, had_err);
        return;
    }
    if key == "expires_in" {
        mark_device_auth_key_seen(seen_mask, 16, had_err);
        read_positive_oauth_int(reader, resp.expires_in_sec, had_err);
        return;
    }
    if key == "interval" {
        mark_device_auth_key_seen(seen_mask, 32, had_err);
        if json::peek(reader) == 'n' {
            json::skip(reader);
        } else {
            read_positive_oauth_int(reader, resp.interval_sec, had_err);
        }
        return;
    }
    json::skip(reader);
}

// ---- PKCE Entropy Pool & Helpers (RFC 7636) ------------------------------

var g_pkce_entropy_counter: u64 = 1;
var g_pkce_entropy_state: u8[32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
    0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
    0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
    0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f,
];

inline fn is_uri_unreserved_bytes(s: const u8[:]) -> bool {
    for b in s {
        guard core::is_uri_unreserved(b) else { return false; }
    }
    return true;
}

inline fn derive_pkce_seed(now_ns: u64, counter: u64) -> u8[32] {
    var buf: u8[..64] = [];
    defer core::secure_zeroize_slice(buf[..]);
    buf.append(g_pkce_entropy_state[..]);
    var meta: u8[16] = [0; 16];
    core::write_le_u64_at(meta[..], 0, now_ns);
    core::write_le_u64_at(meta[..], 8, counter);
    buf.append(meta[..]);

    let round1 = core::sha256(buf[..]);
    for i in 32 {
        g_pkce_entropy_state[i] = round1[i];
    }
    return core::sha256(g_pkce_entropy_state[..]);
}

inline fn generate_derived_verifier<B>(out: B&) -> bool {
    var raw_entropy: u8[32] = [0; 32];
    defer core::secure_zeroize_32(raw_entropy);
    if !core::sim_rng_fill(raw_entropy[..]) {
        g_pkce_entropy_counter = core::add_sat_i64(g_pkce_entropy_counter as i64, 1) as u64;
        raw_entropy = derive_pkce_seed(core::sim_now_ns() as u64, g_pkce_entropy_counter);
    }
    var encoded: u8[..64] = [];
    defer core::secure_zeroize_slice(encoded[..]);
    core::base64url_encode(raw_entropy[..], encoded);
    guard encoded.len >= rfc::PKCE_MIN_VERIFIER_LEN &&
        encoded.len <= rfc::PKCE_MAX_VERIFIER_LEN &&
        is_uri_unreserved_bytes(encoded[..]) else {
        return false;
    }
    guard out.try_set(encoded[..]) else {
        out.resize(0);
        return false;
    }
    return true;
}

// ---- Introspection & Basic Auth Helpers (RFC 7662 / RFC 6749 §2.3.1) -----

// Parses `"aud"` field (single string or array of strings) in an RFC 7662 introspection response.
//
// Example:
//   reader at "\"https://resource.example.org\""
//   returns: ok = true, resp.aud[0] = "https://resource.example.org"
inline fn parse_introspection_aud(reader: json::Reader&, resp: auth::IntrospectionResponse&) -> bool {
    let p = json::peek(reader);
    if p == '"' {
        var item: u8[..128] = [];
        return core::read_json_string_into(reader, item) && item.len > 0 && resp.aud.try_push(item);
    }
    guard p == '[' else {
        json::skip(reader);
        return false;
    }
    var ok = true;
    json::each_element(reader) {
        if json::peek(reader) != '"' {
            json::skip(reader);
            ok = false;
        } else {
            var item: u8[..128] = [];
            if !core::read_json_string_into(reader, item) || item.len == 0 || !resp.aud.try_push(item) {
                ok = false;
            }
        }
    };
    guard ok && resp.aud.len > 0 else {
        resp.aud.clear();
        return false;
    }
    return true;
}

inline fn mark_introspection_key_seen(seen_mask: u32&, bit: u32, had_err: bool&) {
    if (seen_mask & bit) != 0 {
        had_err = true;
    }
    seen_mask = seen_mask | bit;
}

// Reads a JSON string member into `dst` for RFC 7662 introspection metadata.
//
// Example:
//   reader at "\"read write\""
//   sets: dst = "read write", had_err = false
inline fn parse_introspection_str_field<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
    } else if !core::read_json_string_into(reader, dst) {
        had_err = true;
    }
}

// RFC 7519 Section 2: Terminology - NumericDate allows non-negative integer or fractional seconds since Epoch.
//
// Example:
//   reader at "1700000000"
//   sets: dst = 1700000000, had_err = false
inline fn parse_introspection_int_field(reader: json::Reader&, dst: i64&, had_err: bool&) {
    let p = json::peek(reader);
    if core::is_ascii_digit(p) {
        let num = json::read_number(reader);
        if num >= 0.0 && num <= 9223372036854774784.0 {
            dst = num as i64;
        } else {
            had_err = true;
        }
    } else {
        json::skip(reader);
        had_err = true;
    }
}

inline fn read_unique_introspection_str<B>(
    reader:    json::Reader&,
    dst:       B&,
    seen_mask: u32&,
    bit:       u32,
    had_err:   bool&,
) -> bool {
    mark_introspection_key_seen(seen_mask, bit, had_err);
    parse_introspection_str_field(reader, dst, had_err);
    return true;
}

inline fn read_unique_introspection_int(
    reader:    json::Reader&,
    dst:       i64&,
    seen_mask: u32&,
    bit:       u32,
    had_err:   bool&,
) {
    mark_introspection_key_seen(seen_mask, bit, had_err);
    parse_introspection_int_field(reader, dst, had_err);
}

// Parses string metadata fields of an RFC 7662 Token Introspection Response JSON object.
//
// Example:
//   key = "client_id", reader at "\"l23\""
//   sets: resp.client_id = "l23", returns: true
inline fn parse_introspection_str_member(
    key:       const u8[:],
    reader:    json::Reader&,
    resp:      auth::IntrospectionResponse&,
    seen_mask: u32&,
    had_err:   bool&,
) -> bool {
    if key == "scope" { return read_unique_introspection_str(reader, resp.scope, seen_mask, 2, had_err); }
    if key == "client_id" { return read_unique_introspection_str(reader, resp.client_id, seen_mask, 4, had_err); }
    if key == "username" { return read_unique_introspection_str(reader, resp.username, seen_mask, 8, had_err); }
    if key == "token_type" { return read_unique_introspection_str(reader, resp.token_type, seen_mask, 16, had_err); }
    if key == "sub" { return read_unique_introspection_str(reader, resp.sub, seen_mask, 32, had_err); }
    if key == "iss" { return read_unique_introspection_str(reader, resp.iss, seen_mask, 64, had_err); }
    if key == "jti" { return read_unique_introspection_str(reader, resp.jti, seen_mask, 128, had_err); }
    return false;
}

// Parses a single field of an RFC 7662 §2.2 Token Introspection Response JSON object.
//
// Example:
//   key = "active", reader at "true"
//   sets: resp.active = true, seen_mask |= 1
fn parse_introspection_field(
    key:       const u8[:],
    reader:    json::Reader&,
    resp:      auth::IntrospectionResponse&,
    seen_mask: u32&,
    seen_ext:  SeenHeaderKey[..32]&,
    had_err:   bool&,
) {
    if key.contains('\\') {
        json::skip(reader);
        had_err = true;
        return;
    }
    if key == "active" {
        let p = json::peek(reader);
        if (seen_mask & 1) != 0 || (p != 't' && p != 'f') {
            json::skip(reader);
            had_err = true;
        } else {
            resp.active = json::read_bool(reader);
            seen_mask = seen_mask | 1;
        }
        return;
    }
    if parse_introspection_str_member(key, reader, resp, seen_mask, had_err) { return; }
    if key == "aud" {
        mark_introspection_key_seen(seen_mask, 256, had_err);
        if !parse_introspection_aud(reader, resp) { had_err = true; }
        return;
    }
    if key == "exp" { read_unique_introspection_int(reader, resp.exp, seen_mask, 512, had_err); return; }
    if key == "iat" { read_unique_introspection_int(reader, resp.iat, seen_mask, 1024, had_err); return; }
    if key == "nbf" { read_unique_introspection_int(reader, resp.nbf, seen_mask, 2048, had_err); return; }
    // RFC 8725 Section 2.6: Multiplicity of JSON Encodings - reject duplicate extension member names
    if is_header_key_present(key, seen_ext[..]) {
        had_err = true;
    } else {
        var ext_item = SeenHeaderKey { .. };
        if !ext_item.name.try_set(key) || !seen_ext.try_push(ext_item) {
            had_err = true;
        }
    }
    json::skip(reader);
}

// RFC 7617 Section 2: User-id and password MUST NOT contain ASCII control characters (0x00..0x1F, 0x7F) and MUST be valid UTF-8.
inline fn is_valid_basic_auth_credential(s: const u8[:]) -> bool {
    return core::swar_find_ctl(s) == s.len && s.validate_utf8();
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

inline fn try_mark_digest_param(seen_mask: u32&, bit: u32) -> bool {
    guard (seen_mask & bit) == 0 else { return false; }
    seen_mask = seen_mask | bit;
    return true;
}

enum DigestParamStatus {
    Unhandled,
    Applied,
    Invalid,
}

fn apply_digest_core_param(
    chal:      auth::DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
) -> DigestParamStatus {
    if key.eq_ascii_fold("realm") {
        let ok = (seen_mask & 1) == 0 && chal.realm.try_set(val) && try_mark_digest_param(seen_mask, 1);
        return if ok { DigestParamStatus.Applied } else { DigestParamStatus.Invalid };
    }
    if key.eq_ascii_fold("nonce") {
        let ok = (seen_mask & 2) == 0 && chal.nonce.try_set(val) && try_mark_digest_param(seen_mask, 2);
        return if ok { DigestParamStatus.Applied } else { DigestParamStatus.Invalid };
    }
    if key.eq_ascii_fold("algorithm") {
        guard (seen_mask & 4) == 0 && chal.algorithm.try_set(val) && try_mark_digest_param(seen_mask, 4) else {
            return DigestParamStatus.Invalid;
        }
        chal.has_explicit_algo = true;
        return DigestParamStatus.Applied;
    }
    if key.eq_ascii_fold("qop") {
        let qop_ok = (seen_mask & 8) == 0 && val.len > 0 && chal.qop.try_set(val);
        let ok = qop_ok && try_mark_digest_param(seen_mask, 8);
        return if ok { DigestParamStatus.Applied } else { DigestParamStatus.Invalid };
    }
    return DigestParamStatus.Unhandled;
}

fn apply_digest_opt_param(
    chal:      auth::DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
    ext_keys:  u8[..64][..16]&,
) -> bool {
    if key.eq_ascii_fold("opaque") {
        return (seen_mask & 16) == 0 && chal.opaque.try_set(val) && try_mark_digest_param(seen_mask, 16);
    }
    if key.eq_ascii_fold("domain") {
        return (seen_mask & 32) == 0 && chal.domain.try_set(val) && try_mark_digest_param(seen_mask, 32);
    }
    if key.eq_ascii_fold("stale") {
        // RFC 7616 Section 3.3: The WWW-Authenticate Response Header Field - non-"true" stale values mean false
        guard val.len > 0 && try_mark_digest_param(seen_mask, 64) else { return false; }
        chal.stale = val.eq_ascii_fold("true");
        return true;
    }
    if key.eq_ascii_fold("userhash") {
        let is_true = val.eq_ascii_fold("true");
        guard (is_true || val.eq_ascii_fold("false")) && try_mark_digest_param(seen_mask, 128) else { return false; }
        chal.userhash = is_true;
        return true;
    }
    if key.eq_ascii_fold("charset") {
        return val.eq_ascii_fold("UTF-8") && try_mark_digest_param(seen_mask, 256);
    }
    // RFC 9110 Section 11.2: Authentication Parameters - parameter names MUST NOT occur more than once per challenge
    for &seen_ext in ext_keys {
        if seen_ext[..].eq_ascii_fold(key) { return false; }
    }
    var kbuf: u8[..64] = [];
    guard kbuf.try_set(key) && ext_keys.try_push(kbuf) else { return false; }
    seen_mask = seen_mask | 512;
    return true;
}

fn apply_digest_param(
    chal:      auth::DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
    ext_keys:  u8[..64][..16]&,
) -> bool {
    let core_st = apply_digest_core_param(chal, key, val, seen_mask);
    if core_st != DigestParamStatus.Unhandled {
        return core_st == DigestParamStatus.Applied;
    }
    return apply_digest_opt_param(chal, key, val, seen_mask, ext_keys);
}

// Advances `idx` past any leading whitespace, commas, or line breaks (RFC 7616 §3.3).
//
// Example:
//   raw = ",  realm=\"api\"", idx = 0
//   advances `idx` to 3 (pointing to 'r')
fn skip_whitespace_and_commas(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..].trim_start_bytes(" \t,\r\n");
    idx = core::sub_sat_i64(raw.len, rem.len);
}

// Advances `idx` past optional leading "Digest " scheme token (RFC 7616 §3.3).
//
// Example:
//   raw = "Digest realm=\"api\"", idx = 0
//   advances `idx` to 7 (pointing to 'r')
inline fn skip_digest_scheme(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    guard rem.len >= 7 && rem[..6].eq_ascii_fold("digest") else { return; }
    guard rem[6] == ' ' || rem[6] == '\t' else { return; }
    idx = core::add_sat_i64(idx, 7);
}

fn append_escaped_digest_param<B>(out: B&, val: const u8[:]) -> bool {
    for b in val {
        guard b != '\r' && b != '\n' && b != 0 else { return false; }
        if b == '"' || b == '\\' {
            guard out.try_push('\\' as u8) else { return false; }
        }
        guard out.try_push(b) else { return false; }
    }
    return true;
}

fn serialize_digest_opt_kv<B>(
    out:        B&,
    active_qop: const u8[:],
    nc_str:     const u8[:],
    cnonce:     const u8[:],
    opaque:     const u8[:],
    userhash:   bool,
) -> bool {
    if active_qop.len > 0 {
        guard out.try_append(", qop=") && out.try_append(active_qop) else { return false; }
        guard out.try_append(", nc=") && out.try_append(nc_str) else { return false; }
        guard out.try_append(", cnonce=\"") && append_escaped_digest_param(out, cnonce) && out.try_push('"' as u8) else {
            return false;
        }
    } else if cnonce.len > 0 {
        guard out.try_append(", cnonce=\"") && append_escaped_digest_param(out, cnonce) && out.try_push('"' as u8) else {
            return false;
        }
    }

    if opaque.len > 0 {
        guard out.try_append(", opaque=\"") && append_escaped_digest_param(out, opaque) && out.try_push('"' as u8) else {
            return false;
        }
    }

    if userhash {
        guard out.try_append(", userhash=true") else { return false; }
    }

    return true;
}

inline fn sync_opt_buf<B>(dst: B&, src: const u8[:]) -> bool {
    guard src.len > 0 else { return true; }
    return dst.try_set(src);
}

inline fn is_md5_digest_algo(algo: const u8[:]) -> bool {
    return algo.eq_ascii_fold(rfc::DIGEST_ALGO_MD5) || algo.eq_ascii_fold(rfc::DIGEST_ALGO_MD5_SESS);
}

inline fn resolve_stale_digest_algo(
    stored_algo: const u8[:],
    incoming:    const auth::DigestChallenge&,
) -> const u8[:], bool {
    let is_implicit_md5 = !incoming.has_explicit_algo && incoming.algorithm[..].eq_ascii_fold(rfc::DIGEST_ALGO_MD5);
    if is_implicit_md5 && stored_algo.len > 0 {
        return stored_algo, rfc::is_supported_digest_algo(stored_algo);
    }
    guard rfc::is_supported_digest_algo(incoming.algorithm[..]) else { return "", false; }
    if stored_algo.len > 0 && !is_md5_digest_algo(stored_algo) && is_md5_digest_algo(incoming.algorithm[..]) {
        return "", false;
    }
    return incoming.algorithm[..], true;
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

inline fn has_nonzero_byte_32(buf: const u8[32]) -> bool {
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
    core::format_json_key(out, key);
    core::format_json_string(out, val);
    return true;
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
    core::format_json_key(out, key);
    val.format_i64_dec(out);
    return true;
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
            core::format_json_string(out, claims.audiences[i][..]);
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
    core::format_json_key(out, c.key[..]);
    if c.is_num {
        c.val_num.format_i64_dec(out);
    } else if c.is_bool {
        guard out.try_append(if c.val_bool { "true" } else { "false" }) else { return false; }
    } else {
        core::format_json_string(out, c.val_str[..]);
    }
    return true;
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
