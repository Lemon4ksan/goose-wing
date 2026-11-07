// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Proof Key for Code Exchange by OAuth Public Clients (RFC 7636 / RFC 9700 Security BCP).
// Implements secure S256 code challenge generation and constant-time validation.
namespace wing;

import std;
import json;
import core from "..";

// ---- PKCE Constants -------------------------------------------------------

struct PkcePair {
    verifier:  u8[..128] = [],
    challenge: u8[..128] = [],
    method:    u8[..16]  = "S256",
}

const BASE64URL_CHAR_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false,
    true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, true,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

checkfree inline fn is_base64url_char(ch: u8) -> bool {
    return BASE64URL_CHAR_LUT[ch];
}

const CANONICAL_S256_FINAL_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    true, false, false, false, true, false, false, false, true, false, false, false, false, false, false, false,
    false, true, false, false, false, true, false, false, false, true, false, false, false, true, false, false,
    false, true, false, false, false, true, false, false, false, true, false, false, false, false, false, false,
    false, false, false, true, false, false, false, true, false, false, false, true, false, false, false, true,
    false, false, false, true, false, false, false, true, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

// RFC 7636 §4.2 / RFC 4648 §3.5: Verifies that the 43rd Base64URL character of an S256
// challenge has bits 1..0 set to 00 (canonical padding bits).
checkfree inline fn is_canonical_s256_final_char(ch: u8) -> bool {
    return CANONICAL_S256_FINAL_LUT[ch];
}

// Validates whether verifier conforms to RFC 7636 Section 4.1.
fn is_valid_code_verifier(v: const u8[:]) -> bool {
    guard v.len >= rfc::PKCE_MIN_VERIFIER_LEN && v.len <= rfc::PKCE_MAX_VERIFIER_LEN else {
        return false;
    }
    for b in v {
        guard core::is_uri_unreserved(b) else {
            return false;
        }
    }
    return true;
}

var g_pkce_entropy_counter: u64 = 1;
var g_pkce_entropy_state: u8[32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
    0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
    0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
    0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f,
];

// Validates whether code_challenge conforms to RFC 7636 Section 4.2.
// Defaults to 'plain' when method is omitted per RFC 7636 §4.3.
// S256: exactly 43 unpadded base64url characters with canonical padding bits.
// plain: 43..128 unreserved characters (same as code_verifier).
fn is_valid_code_challenge(challenge: const u8[:], method: const u8[:] = "plain") -> bool {
    let eff_method = if method.len == 0 { rfc::PKCE_METHOD_PLAIN } else { method };
    if eff_method == rfc::PKCE_METHOD_S256 {
        guard challenge.len == 43 else { return false; }
        for i in 42 {
            guard is_base64url_char(challenge[i]) else { return false; }
        }
        guard is_canonical_s256_final_char(challenge[42]) else { return false; }
        return true;
    } else if eff_method == rfc::PKCE_METHOD_PLAIN {
        return is_valid_code_verifier(challenge);
    }
    return false;
}

// Encodes caller-provided entropy bytes into a base64url PKCE verifier (RFC 7636 §4.1).
inline fn encode_external_entropy<B>(entropy: const u8[:], out: B&) -> bool {
    let max_raw = min(entropy.len, 96);
    var encoded: u8[..128] = [];
    core::base64url_encode(entropy[..max_raw], encoded);
    guard out.try_set(encoded[..]) else { return false; }
    return is_valid_code_verifier(out[..]);
}

inline fn derive_pkce_seed(now_ns: u64, counter: u64) -> u8[32] {
    var buf: u8[..64] = [];
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
    guard out.cap >= 43 else { return false; }
    g_pkce_entropy_counter = core::add_sat_i64(g_pkce_entropy_counter as i64, 1) as u64;
    let raw_entropy = derive_pkce_seed(clock_ns() as u64, g_pkce_entropy_counter);
    core::base64url_encode(raw_entropy[..], out);
    return is_valid_code_verifier(out[..]);
}

// Generates a valid PKCE code verifier (43..128 characters) into out (RFC 7636 §4.1).
// If entropy bytes (>= 32 bytes) are provided, encodes them into URL-safe characters.
// If empty, derives high-entropy dynamic bytes by mixing monotonic clock (clock_ns),
// global monotonic counter, and multi-round SHA-256 cryptographic expansion (FINDING-R5-SEC-07).
// Returns false if entropy is non-empty but less than 32 bytes (256 bits).
//
// Example:
//   entropy = "", out = []
//   returns: ok = true, out = "..." (43 URL-safe unreserved characters)
fn generate_code_verifier<B>(out: B&, entropy: const u8[:] = "") -> bool {
    out.clear();
    guard entropy.len == 0 || entropy.len >= 32 else {
        return false; // RFC 7636 §4.1: Minimum 256 bits (32 bytes) of entropy required
    }
    if entropy.len >= 32 {
        return encode_external_entropy(entropy, out);
    }
    return generate_derived_verifier(out);
}

// Computes code_challenge from code_verifier using S256 or plain (RFC 7636 Section 4.2).
// S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
// Method MUST be case-sensitive ("S256" or "plain", RFC 7636 Section 4.3). Defaults to 'plain'.
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool {
    out.clear();
    guard is_valid_code_verifier(verifier) else {
        return false;
    }
    let eff_method = if method.len == 0 { rfc::PKCE_METHOD_PLAIN } else { method };
    guard eff_method == rfc::PKCE_METHOD_S256 || eff_method == rfc::PKCE_METHOD_PLAIN else {
        return false;
    }
    let needed = if eff_method == rfc::PKCE_METHOD_S256 { 43 } else { verifier.len };
    guard needed <= out.cap else {
        return false;
    }

    if eff_method == rfc::PKCE_METHOD_S256 {
        let digest = core::sha256(verifier);
        core::base64url_encode(digest[..], out);
    } else {
        out.append(verifier);
    }
    return true;
}

// Constant-time validation of code_verifier against code_challenge (RFC 7636 Section 4.6).
// Defaults to 'plain' when method is omitted per RFC 7636 §4.3.
fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "plain") -> bool {
    let eff_method = if method.len == 0 { rfc::PKCE_METHOD_PLAIN } else { method };
    guard is_valid_code_verifier(verifier) else {
        return false;
    }
    guard is_valid_code_challenge(challenge, eff_method) else {
        return false;
    }

    var computed: u8[..128] = [];
    guard compute_code_challenge(verifier, eff_method, computed) else {
        return false;
    }

    guard computed.len == challenge.len else {
        return false;
    }

    return core::ct_eq_bytes(computed[..], challenge);
}

// Creates a complete PKCE challenge pair. Returns false if entropy or method is invalid.
fn create_pkce_pair(entropy: const u8[:] = "", method: const u8[:] = "S256") -> PkcePair, bool {
    var pair = PkcePair { method: "", .. };
    let empty_pair = PkcePair { method: "", .. };
    let eff_method = if method.len == 0 { rfc::PKCE_METHOD_PLAIN } else { method };
    guard pair.method.try_set(eff_method) else { return empty_pair, false; }
    guard generate_code_verifier(pair.verifier, entropy) else { return empty_pair, false; }
    guard compute_code_challenge(pair.verifier[..], eff_method, pair.challenge) else { return empty_pair, false; }
    return pair, true;
}

// ---- OAuth 2.1 & RFC 9700 Security BCP Enforcement -----------------------

// Validates whether code_challenge conforms to OAuth 2.1 Section 7.6.1 and RFC 9700 Section 2.1.1.
// Strictly mandates S256 and forbids the legacy plain transformation.
fn is_valid_code_challenge_strict(challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    guard method == rfc::PKCE_METHOD_S256 else { return false; }
    return is_valid_code_challenge(challenge, method);
}

// Validates code_verifier against code_challenge under OAuth 2.1 / RFC 9700 strict rules.
// Rejects method != "S256" immediately.
fn validate_code_challenge_strict(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    guard method == rfc::PKCE_METHOD_S256 else { return false; }
    return validate_code_challenge(verifier, challenge, method);
}

// ---- RFC 8628 OAuth 2.0 Device Authorization Grant -----------------------

const DEFAULT_DEVICE_POLL_INTERVAL_SEC: i64 = 5;
const DEVICE_SLOW_DOWN_INCREMENT_SEC:   i64 = 5;

struct DeviceAuthResponse {
    device_code:               u8[..128] = [],
    user_code:                 u8[..32]  = [],
    verification_uri:          u8[..256] = [],
    verification_uri_complete: u8[..256] = [],
    expires_in_sec:            i64       = 0,
    interval_sec:              i64       = DEFAULT_DEVICE_POLL_INTERVAL_SEC,
}

enum DevicePollStatus {
    Granted,
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    TransportError,
}

// Reads a required non-empty JSON string field into `dst`.
//
// Example:
//   reader at "\"WDJB-MJHT\""
//   sets: dst = "WDJB-MJHT", had_err = false
inline fn read_required_oauth_str<B>(reader: json::Reader&, scratch: u8[>..]&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
        return;
    }
    let s = json::read_string(reader, scratch);
    if s.len == 0 || !dst.try_set(s) {
        had_err = true;
    }
}

// Reads an optional nullable JSON string field into `dst`.
//
// Example:
//   reader at "\"https://ex.com?code=1\""
//   sets: dst = "https://ex.com?code=1", had_err = false
inline fn read_nullable_oauth_str<B>(reader: json::Reader&, scratch: u8[>..]&, dst: B&, had_err: bool&) {
    let p = json::peek(reader);
    if p == 'n' {
        json::skip(reader);
    } else if p != '"' || !dst.try_set(json::read_string(reader, scratch)) {
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
    if p >= '0' && p <= '9' {
        dst = json::read_int(reader);
        if dst <= 0 { had_err = true; }
    } else {
        json::skip(reader);
        had_err = true;
    }
}

// Parses a single field of an RFC 8628 §3.2 Device Authorization Response JSON object.
//
// Example:
//   key = "user_code", reader at "\"WDJB-MJHT\""
//   sets: out.user_code = "WDJB-MJHT", had_err = false
inline fn parse_device_auth_field(
    key:     const u8[:],
    reader:  json::Reader&,
    scratch: u8[>..]&,
    out:     DeviceAuthResponse&,
    had_err: bool&,
) {
    if key == "device_code" { read_required_oauth_str(reader, scratch, out.device_code, had_err); return; }
    if key == "user_code" { read_required_oauth_str(reader, scratch, out.user_code, had_err); return; }
    if key == "verification_uri" || key == "verification_url" {
        read_required_oauth_str(reader, scratch, out.verification_uri, had_err);
        return;
    }
    if key == "verification_uri_complete" {
        read_nullable_oauth_str(reader, scratch, out.verification_uri_complete, had_err);
        return;
    }
    if key == "expires_in" { read_positive_oauth_int(reader, out.expires_in_sec, had_err); return; }
    if key == "interval" {
        let p = json::peek(reader);
        if p == 'n' {
            json::skip(reader);
        } else if p >= '0' && p <= '9' {
            out.interval_sec = max(json::read_int(reader), DEFAULT_DEVICE_POLL_INTERVAL_SEC);
        } else {
            json::skip(reader);
            had_err = true;
        }
        return;
    }
    json::skip(reader);
}

// Parses an RFC 8628 §3.2 Device Authorization Response JSON document.
// Accepts both standard `"verification_uri"` and legacy `"verification_url"` alias.
//
// Example:
//   raw_json = "{\"device_code\":\"GmRhm\",\"user_code\":\"WDJB\",\"verification_uri\":\"https://ex.com/dev\",\"expires_in\":1800}"
//   returns: out with interval_sec = 5, ok = true
fn parse_device_auth_response(raw_json: const u8[:]) -> DeviceAuthResponse, bool {
    var out = DeviceAuthResponse { .. };
    let empty = DeviceAuthResponse { .. };
    guard raw_json.len > 0 && raw_json.len <= 4096 else { return empty, false; }
    var reader = json::reader(raw_json);
    var scratch: u8[>..] = [];
    var had_err = false;
    json::each_member(reader) { key =>
        scratch.clear();
        parse_device_auth_field(key, reader, scratch, out, had_err);
    };
    let complete = out.device_code.len > 0 && out.user_code.len > 0 &&
                   out.verification_uri.len > 0 && out.expires_in_sec > 0;
    guard json::finish(reader) && !had_err && complete else {
        return empty, false;
    }
    return out, true;
}

// Advances the RFC 8628 §3.5 Device Access Token polling interval state machine.
// Returns `(next_interval_sec, should_continue_polling)`.
fn step_device_poll_interval(
    current_interval_sec: i64,
    max_backoff_sec:      i64,
    status:               DevicePollStatus,
) -> i64, bool {
    let base = max(current_interval_sec, DEFAULT_DEVICE_POLL_INTERVAL_SEC);
    let ceiling = max(max_backoff_sec, base);
    match status {
        Granted => { return 0, false; },
        AuthorizationPending => { return base, true; },
        SlowDown => { return min(core::add_sat_i64(base, DEVICE_SLOW_DOWN_INCREMENT_SEC), ceiling), true; },
        TransportError => { return min(core::add_sat_i64(base, base), ceiling), true; },
        AccessDenied => { return base, false; },
        ExpiredToken => { return base, false; },
    }
}

// ---- RFC 7009 Token Revocation & RFC 7662 Token Introspection ------------

enum TokenTypeHint {
    None,
    AccessToken,
    RefreshToken,
}

struct IntrospectionResponse {
    active:     bool           = false,
    scope:      u8[..256]      = [],
    client_id:  u8[..128]      = [],
    username:   u8[..128]      = [],
    token_type: u8[..32]       = [],
    sub:        u8[..128]      = [],
    iss:        u8[..128]      = [],
    jti:        u8[..128]      = [],
    aud:        u8[..128][..8] = [],
    exp:        i64            = -1,
    iat:        i64            = -1,
    nbf:        i64            = -1,
}

const UPPER_HEX_DIGITS: const u8[16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

inline fn is_form_urlencode_safe(b: u8) -> bool {
    if b >= 'A' && b <= 'Z' { return true; }
    if b >= 'a' && b <= 'z' { return true; }
    if b >= '0' && b <= '9' { return true; }
    return b == '-' || b == '.' || b == '_' || b == '*';
}

inline fn append_form_urlencoded(src: const u8[:], dst: u8[..1024]&) -> bool {
    var temp: u8[..1024] = [];
    let rem = core::sub_sat_i64(dst.cap, dst.len);
    for b in src {
        if b == ' ' || is_form_urlencode_safe(b) {
            guard temp.len < rem else { return false; }
            temp.push(if b == ' ' { '+' } else { b });
        } else {
            guard core::sub_sat_i64(rem, temp.len) >= 3 else { return false; }
            temp.push('%');
            temp.push(UPPER_HEX_DIGITS[((b >> 4) & 0x0F) as i64]);
            temp.push(UPPER_HEX_DIGITS[(b & 0x0F) as i64]);
        }
    }
    dst.append(temp[..]);
    return true;
}

// Encodes an RFC 7009 §2.1 / RFC 7662 §2.1 `application/x-www-form-urlencoded` request body
// containing `token=<urlencoded>` and optional `&token_type_hint=<hint>`.
//
// Example:
//   token = "sec/ret+1", hint = TokenTypeHint.AccessToken
//   returns: ok = true, out = "token=sec%2Fret%2B1&token_type_hint=access_token"
fn encode_token_endpoint_form<B>(token: const u8[:], hint: TokenTypeHint, out: B&) -> bool {
    out.clear();
    guard token.len > 0 && token.len <= 256 else { return false; }
    var buf: u8[..1024] = [];
    buf.append("token=");
    guard append_form_urlencoded(token, buf) else { return false; }
    if hint == TokenTypeHint.AccessToken {
        buf.append("&token_type_hint=access_token");
    } else if hint == TokenTypeHint.RefreshToken {
        buf.append("&token_type_hint=refresh_token");
    }
    return out.try_set(buf[..]);
}

// Parses `"aud"` field (single string or array of strings) in an RFC 7662 introspection response.
//
// Example:
//   reader at "\"https://resource.example.org\""
//   returns: ok = true, out.aud[0] = "https://resource.example.org"
inline fn parse_introspection_aud(reader: json::Reader&, scratch: u8[>..]&, out: IntrospectionResponse&) -> bool {
    let p = json::peek(reader);
    if p == '"' {
        let s = json::read_string(reader, scratch);
        guard s.len > 0 && s.len <= 128 && out.aud.len < out.aud.cap else { return false; }
        var item: u8[..128] = [];
        item.append(s);
        out.aud.push(item);
        return true;
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
            scratch.clear();
            let s = json::read_string(reader, scratch);
            if s.len == 0 || s.len > 128 || out.aud.len >= out.aud.cap {
                ok = false;
            } else {
                var item: u8[..128] = [];
                item.append(s);
                out.aud.push(item);
            }
        }
    };
    return ok;
}

// Reads a JSON string member into `dst` for RFC 7662 introspection metadata.
//
// Example:
//   reader at "\"read write\""
//   sets: dst = "read write", had_err = false
inline fn parse_introspection_str_field<B>(reader: json::Reader&, scratch: u8[>..]&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
    } else if !dst.try_set(json::read_string(reader, scratch)) {
        had_err = true;
    }
}

// Reads a non-negative JSON integer timestamp for RFC 7662 introspection metadata (`exp`, `iat`, `nbf`).
//
// Example:
//   reader at "1700000000"
//   sets: dst = 1700000000, had_err = false
inline fn parse_introspection_int_field(reader: json::Reader&, dst: i64&, had_err: bool&) {
    let p = json::peek(reader);
    if p >= '0' && p <= '9' {
        dst = json::read_int(reader);
    } else {
        json::skip(reader);
        had_err = true;
    }
}

// Parses string metadata fields of an RFC 7662 Token Introspection Response JSON object.
//
// Example:
//   key = "client_id", reader at "\"l23\""
//   sets: out.client_id = "l23", returns: true
inline fn parse_introspection_str_member(
    key:     const u8[:],
    reader:  json::Reader&,
    scratch: u8[>..]&,
    out:     IntrospectionResponse&,
    had_err: bool&,
) -> bool {
    if key == "scope" { parse_introspection_str_field(reader, scratch, out.scope, had_err); return true; }
    if key == "client_id" { parse_introspection_str_field(reader, scratch, out.client_id, had_err); return true; }
    if key == "username" { parse_introspection_str_field(reader, scratch, out.username, had_err); return true; }
    if key == "token_type" { parse_introspection_str_field(reader, scratch, out.token_type, had_err); return true; }
    if key == "sub" { parse_introspection_str_field(reader, scratch, out.sub, had_err); return true; }
    if key == "iss" { parse_introspection_str_field(reader, scratch, out.iss, had_err); return true; }
    if key == "jti" { parse_introspection_str_field(reader, scratch, out.jti, had_err); return true; }
    return false;
}

// Parses a single field of an RFC 7662 §2.2 Token Introspection Response JSON object.
//
// Example:
//   key = "active", reader at "true"
//   sets: out.active = true, seen_active = true
inline fn parse_introspection_field(
    key:         const u8[:],
    reader:      json::Reader&,
    scratch:     u8[>..]&,
    out:         IntrospectionResponse&,
    seen_active: bool&,
    had_err:     bool&,
) {
    if key == "active" {
        let p = json::peek(reader);
        if seen_active || (p != 't' && p != 'f') {
            json::skip(reader);
            had_err = true;
        } else {
            out.active = json::read_bool(reader);
            seen_active = true;
        }
        return;
    }
    if parse_introspection_str_member(key, reader, scratch, out, had_err) { return; }
    if key == "aud" {
        if !parse_introspection_aud(reader, scratch, out) { had_err = true; }
        return;
    }
    if key == "exp" { parse_introspection_int_field(reader, out.exp, had_err); return; }
    if key == "iat" { parse_introspection_int_field(reader, out.iat, had_err); return; }
    if key == "nbf" { parse_introspection_int_field(reader, out.nbf, had_err); return; }
    json::skip(reader);
}

// Parses an RFC 7662 §2.2 Token Introspection Response JSON document.
// Requires `"active"` to be explicitly present as a JSON boolean and clears metadata when `active == false`.
//
// Example:
//   raw_json = "{\"active\":true,\"client_id\":\"l23\",\"sub\":\"Z5O\"}"
//   returns: out.active = true, out.client_id = "l23", ok = true
fn parse_introspection_response(raw_json: const u8[:]) -> IntrospectionResponse, bool {
    var out = IntrospectionResponse { .. };
    let empty = IntrospectionResponse { .. };
    guard raw_json.len > 0 && raw_json.len <= 4096 else { return empty, false; }
    var reader = json::reader(raw_json);
    var scratch: u8[>..] = [];
    var seen_active = false;
    var had_err = false;
    json::each_member(reader) { key =>
        scratch.clear();
        parse_introspection_field(key, reader, scratch, out, seen_active, had_err);
    };
    guard json::finish(reader) && !had_err && seen_active else {
        return empty, false;
    }
    if !out.active {
        return empty, true;
    }
    return out, true;
}

// ---- RFC 6749 §2.3.1 OAuth 2.0 `client_secret_basic` Credentials ---------

// Encodes `client_id` and `client_secret` into an RFC 6749 §2.3.1 `Authorization: Basic ...` header value
// by applying `application/x-www-form-urlencoded` to each component before joining with `':'` and Base64-encoding.
//
// Example:
//   client_id = "a:b", client_secret = "c d"
//   returns: ok = true, out_header_val = "Basic YSUzQWI6Yytk"
fn encode_oauth2_basic_auth<B>(
    client_id:      const u8[:],
    client_secret:  const u8[:],
    out_header_val: B&,
) -> bool {
    out_header_val.clear();
    guard client_id.len <= 256 && client_secret.len <= 256 else { return false; }
    guard core::index_of_byte(client_id, 0) == -1 && core::index_of_byte(client_secret, 0) == -1 else {
        return false;
    }
    var cred_buf: u8[..1024] = [];
    guard append_form_urlencoded(client_id, cred_buf) else { return false; }
    guard cred_buf.len < cred_buf.cap else { return false; }
    cred_buf.push(':');
    guard append_form_urlencoded(client_secret, cred_buf) else { return false; }

    var b64_buf: u8[..1536] = [];
    b64_buf.append("Basic ");
    core::base64_encode(cred_buf[..], b64_buf);
    core::secure_zeroize_slice(cred_buf[..]);
    return out_header_val.try_set(b64_buf[..]);
}

const FORM_HEX_NIBBLE_LUT: const u8[256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

const FORM_HEX_HI_LUT: const u8[256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 255, 255, 255, 255, 255, 255,
    255, 160, 176, 192, 208, 224, 240, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 160, 176, 192, 208, 224, 240, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

// Decodes an `application/x-www-form-urlencoded` slice into `out`.
//
// Example:
//   src = "a%3Ab+c"
//   returns: ok = true, out = "a:b c"
inline fn decode_form_urlencoded(src: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    var temp: u8[..256] = [];
    var i:    i64       = 0;
    while i < src.len {
        guard temp.len < temp.cap else { return false; }
        let b = src[i];
        if b == '+' {
            temp.push(' ');
            i = core::add_sat_i64(i, 1);
        } else if b == '%' {
            let i1 = core::add_sat_i64(i, 1);
            let i2 = core::add_sat_i64(i, 2);
            guard i2 < src.len else { return false; }
            let hi = FORM_HEX_HI_LUT[src[i1]];
            let lo = FORM_HEX_NIBBLE_LUT[src[i2]];
            guard hi != 255 && lo <= 15 else { return false; }
            let decoded = hi | lo;
            guard decoded != 0 else { return false; }
            temp.push(decoded);
            i = core::add_sat_i64(i, 3);
        } else {
            guard b != 0 else { return false; }
            temp.push(b);
            i = core::add_sat_i64(i, 1);
        }
    }
    out.append(temp[..]);
    core::secure_zeroize_slice(temp[..]);
    return true;
}

// Decodes an RFC 6749 §2.3.1 `Authorization: Basic ...` header value into `out_id` and `out_secret`,
// reversing Base64 and `application/x-www-form-urlencoded` on each component.
//
// Example:
//   header_val = "Basic YSUzQWI6Yytk"
//   returns: ok = true, out_id = "a:b", out_secret = "c d"
fn decode_oauth2_basic_auth(
    header_val: const u8[:],
    out_id:     u8[..256]&,
    out_secret: u8[..256]&,
) -> bool {
    out_id.clear();
    out_secret.clear();
    guard header_val.len > 6 && header_val.len <= 2048 else { return false; }
    guard core::starts_with_fold(header_val, "Basic ") else { return false; }
    let b64_part = core::trim_lws(header_val[6..]);
    guard b64_part.len > 0 else { return false; }

    var raw_cred: u8[..1024] = [];
    guard core::base64_decode(b64_part, raw_cred) else { return false; }
    let colon = core::index_of_byte(raw_cred[..], ':');
    guard colon >= 0 else {
        core::secure_zeroize_slice(raw_cred[..]);
        return false;
    }
    let sec_start = core::add_sat_i64(colon, 1);
    let ok_id = decode_form_urlencoded(raw_cred[..colon], out_id);
    let ok_sec = decode_form_urlencoded(raw_cred[sec_start..], out_secret);
    core::secure_zeroize_slice(raw_cred[..]);
    guard ok_id && ok_sec else {
        out_id.clear();
        out_secret.clear();
        return false;
    }
    return true;
}
