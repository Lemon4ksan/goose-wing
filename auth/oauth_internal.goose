// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal OAuth 2.0 helpers for ACME, Device Grant, PKCE, Introspection, and Basic Auth.
namespace auth_internal;

import std;
import json;
import core;
import rfc.http;
import .types;
import .internal;

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
    // RFC 8628 Section 3.2 & Section 5.4: Device verification URIs MUST use HTTPS.
    return parsed.scheme().eq_ascii_fold("https");
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

// ---- PKCE Entropy Helpers (RFC 7636) -------------------------------------

inline fn is_uri_unreserved_bytes(s: const u8[:]) -> bool {
    for b in s {
        guard core::is_uri_unreserved(b) else { return false; }
    }
    return true;
}

inline fn generate_derived_verifier<B>(out: B&) -> bool {
    var raw_entropy: u8[32] = [0; 32];
    defer core::secure_zeroize_32(raw_entropy);
    // RFC 7636 Section 4.1: Code verifier entropy MUST come from a CSPRNG (or active DST sim RNG).
    let got_rng = if core::sim_rng_is_active() {
        core::sim_rng_fill(raw_entropy[..])
    } else {
        core::csprng_fill(raw_entropy[..])
    };
    guard got_rng else { return false; }
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
            dst = num as! i64;
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

// Parses the unique RFC 7662 `"active"` boolean member from `reader`.
//
// Example:
//   reader at "true", seen_mask = 0
//   sets: resp.active = true, seen_mask |= 1
inline fn parse_introspection_active(
    reader:    json::Reader&,
    resp:      auth::IntrospectionResponse&,
    seen_mask: u32&,
    had_err:   bool&,
) {
    let p = json::peek(reader);
    if (seen_mask & 1) != 0 || (p != 't' && p != 'f') {
        json::skip(reader);
        had_err = true;
        return;
    }
    resp.active = json::read_bool(reader);
    seen_mask = seen_mask | 1;
}

inline fn record_introspection_ext_key(
    key:      const u8[:],
    seen_ext: SeenHeaderKey[..32]&,
    had_err:  bool&,
) {
    // RFC 8725 Section 2.6: Multiplicity of JSON Encodings - reject duplicate extension member names
    if is_header_key_present(key, seen_ext[..]) {
        had_err = true;
        return;
    }
    var ext_item = SeenHeaderKey { .. };
    if !ext_item.name.try_set(key) || !seen_ext.try_push(ext_item) {
        had_err = true;
    }
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
    if key == "active" { parse_introspection_active(reader, resp, seen_mask, had_err); return; }
    if parse_introspection_str_member(key, reader, resp, seen_mask, had_err) { return; }
    if key == "aud" {
        mark_introspection_key_seen(seen_mask, 256, had_err);
        if !parse_introspection_aud(reader, resp) { had_err = true; }
        return;
    }
    if key == "exp" { read_unique_introspection_int(reader, resp.exp, seen_mask, 512, had_err); return; }
    if key == "iat" { read_unique_introspection_int(reader, resp.iat, seen_mask, 1024, had_err); return; }
    if key == "nbf" { read_unique_introspection_int(reader, resp.nbf, seen_mask, 2048, had_err); return; }
    record_introspection_ext_key(key, seen_ext, had_err);
    json::skip(reader);
}

// RFC 7617 Section 2: User-id and password MUST NOT contain ASCII control characters (0x00..0x1F, 0x7F) and MUST be valid UTF-8.
inline fn is_valid_basic_auth_credential(s: const u8[:]) -> bool {
    return core::swar_find_ctl(s) == s.len && !s.contains_byte(0x7F) && s.validate_utf8();
}
