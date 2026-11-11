// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7519 JSON Web Token (JWT) and RFC 7515 JSON Web Signature (JWS) engine.
// Symmetric HMAC (HS256, HS384, HS512) and asymmetric Ed25519 (EdDSA / RFC 8037).
// RFC 8725 BCP security defenses: algorithm pinning, none-alg rejection, clock leeway.
namespace wing;

import std;
import json;
import core from "..";

// Cryptographic key and signature sizes
const DEFAULT_JWT_LEEWAY_SECONDS: i64 = 60;

// ---- JWT / JWS Algorithm & Error Models ----------------------------------

enum JwtAlg {
    Unspecified, // Omitted in key/options (RFC 7517 §4.4)
    None,        // Explicit "none" algorithm (RFC 7518 §3.6, disallowed by default per RFC 8725 §3.1)
    HS256,       // HMAC using SHA-256 (RFC 7518 Section 3.2)
    HS384,       // HMAC using SHA-384
    HS512,       // HMAC using SHA-512
    EdDSA,       // Ed25519 digital signature (RFC 8037 Section 3.1)
    ES256,       // ECDSA using P-256 and SHA-256 (RFC 7518 Section 3.4)
    RS256,       // RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 Section 3.3)
    PS256,       // RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 Section 3.5)
    Unknown,     // Unsupported or unrecognized algorithm (RFC 7515 §4.1.1)
}

fn jwt_alg_to_string(alg: JwtAlg) -> const u8[:] {
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

// RFC 7518 Section 3: Cryptographic Algorithms for Digital Signatures and MACs - Parses a JWS algorithm token into a typed JwtAlg.
//
// Example:
//   s = "HS256"
//   returns: JwtAlg.HS256
fn parse_jwt_alg(s: const u8[:]) -> JwtAlg {
    if s == "HS256" { return JwtAlg.HS256; }
    if s == "HS384" { return JwtAlg.HS384; }
    if s == "HS512" { return JwtAlg.HS512; }
    if s == "EdDSA" { return JwtAlg.EdDSA; }
    if s == "ES256" { return JwtAlg.ES256; }
    if s == "RS256" { return JwtAlg.RS256; }
    if s == "PS256" { return JwtAlg.PS256; }
    if s == "none" { return JwtAlg.None; }
    return JwtAlg.Unknown;
}

enum JwtError {
    None,
    MalformedToken,            // Missing dots, wrong part count (must be exactly 3 parts)
    InvalidBase64,             // Base64URL decoding failed
    InvalidHeaderJson,         // Header JSON could not be parsed
    InvalidClaimsJson,         // Claims JSON could not be parsed
    UnsupportedAlgorithm,      // Unknown algorithm or 'none' when not explicitly allowed
    AlgorithmMismatch,         // Token header alg does not match expected verification alg
    SignatureInvalid,          // Cryptographic signature check failed
    TokenExpired,              // exp claim is before now - leeway
    TokenNotYetValid,          // nbf claim is after now + leeway
    IssuerMismatch,            // iss claim does not match expected issuer
    AudienceMismatch,          // aud claim does not match expected audience
    SubjectMismatch,           // sub claim does not match expected subject
    KeyNotFound,               // kid requested by token not found in JWKS
    CriticalHeaderUnsupported, // crit header contains unsupported param (RFC 7515 §4.1.11 / RFC 8725 §3.8)
    TypeMismatch,              // typ header does not match expected type (RFC 8725 §3.11 / RFC 9068)
}

// ---- JWT Header Model & Parser -------------------------------------------

struct CritParam {
    name: u8[..32] = [],
}

struct JwtHeader {
    alg:     JwtAlg         = JwtAlg.HS256,
    typ:     u8[..32]       = "JWT",
    kid:     u8[..64]       = [],
    cty:     u8[..32]       = [],
    crit:    CritParam[..8] = [],
    b64:     bool           = true,
    has_b64: bool           = false,
}

fn new_jwt_header(alg: JwtAlg = JwtAlg.HS256, kid: const u8[:] = "") -> JwtHeader {
    var hdr = JwtHeader {
        alg: alg,
        ..
    };
    if kid.len > 0 {
        let _ = hdr.kid.try_set(kid);
    }
    return hdr;
}

fn add_header_crit(header: JwtHeader&, name: const u8[:]) -> bool {
    guard name.len > 0 && !rfc::is_standard_jws_header_param(name) else { return false; }
    for &cp in header.crit {
        guard cp.name[..] != name else { return false; }
    }
    var item = CritParam { .. };
    return item.name.try_set(name) && header.crit.try_push(item);
}

fn serialize_jwt_header<B>(header: const JwtHeader&, out: B&) {
    out.append("{\"alg\":");
    core::format_json_string(out, jwt_alg_to_string(header.alg));
    if header.typ.len > 0 {
        out.append(",\"typ\":");
        core::format_json_string(out, header.typ[..]);
    }
    if header.kid.len > 0 {
        out.append(",\"kid\":");
        core::format_json_string(out, header.kid[..]);
    }
    if header.cty.len > 0 {
        out.append(",\"cty\":");
        core::format_json_string(out, header.cty[..]);
    }
    if header.has_b64 {
        out.append(if header.b64 { ",\"b64\":true" } else { ",\"b64\":false" });
    }
    if header.crit.len > 0 {
        out.append(",\"crit\":[");
        for i in header.crit.len {
            if i > 0 { out.push(','); }
            core::format_json_string(out, header.crit[i].name[..]);
        }
        out.push(']');
    }
    out.push('}');
}

struct SeenHeaderKey {
    name: u8[..64] = [],
}

// Parses critical header parameters from JSON array (RFC 7515 §4.1.11).
//
// Example:
//   reader at "[\"b64\",\"claim\"]"
//   returns: out_crit with 2 elements, had_error = false
inline fn parse_crit_header_elements(
    reader:    json::Reader&,
    out_crit:  CritParam[..8]&,
    had_error: bool&,
) {
    json::each_element(reader) {
        var cp = CritParam { .. };
        if !core::read_json_string_into(reader, cp.name) {
            had_error = true;
            return;
        }
        let crit_name = cp.name[..];
        if crit_name.len == 0 || crit_name.contains('\\') || rfc::is_standard_jws_header_param(crit_name) {
            had_error = true;
        }
        for &existing in out_crit {
            if existing.name[..] == crit_name {
                had_error = true; // RFC 7515 §4.1.11: senders MUST NOT use duplicate names
            }
        }
        if crit_name.len == 0 || !out_crit.try_push(cp) {
            had_error = true;
        }
    };
    if out_crit.len == 0 {
        had_error = true;
    }
}

inline fn is_header_key_present(name: const u8[:], seen: const SeenHeaderKey[:]) -> bool {
    for &o in seen {
        if o.name[..] == name { return true; }
    }
    return false;
}

// Reads a non-empty JSON string header parameter into `dst` and rejects duplicates.
//
// Example:
//   reader at "\"JWT\"", seen = false
//   sets dst = "JWT", seen = true, had_error = false
inline fn parse_jwt_header_str<B>(
    reader:    json::Reader&,
    dst:       B&,
    seen:      bool&,
    had_error: bool&,
) {
    if seen { had_error = true; }
    seen = true;
    guard json::peek(reader) == '"' else {
        json::skip(reader);
        had_error = true;
        return;
    }
    if !core::read_json_string_into(reader, dst) || dst.len == 0 {
        had_error = true;
    }
}

// Parses a single member of a JWT header JSON object.
//
// Example:
//   key = "alg", reader at "\"HS256\""
//   returns: out_header.alg = JwtAlg.HS256, seen_alg = true
inline fn parse_jwt_header_member(
    key:         const u8[:],
    reader:      json::Reader&,
    out_header:  JwtHeader&,
    seen_alg:    bool&,
    seen_typ:    bool&,
    seen_kid:    bool&,
    seen_cty:    bool&,
    seen_crit:   bool&,
    seen_others: SeenHeaderKey[..8]&,
    had_error:   bool&,
) {
    if key == "alg" {
        if seen_alg || json::peek(reader) != '"' { had_error = true; }
        seen_alg = true;
        var alg_buf: u8[..16] = [];
        if core::read_json_string_into(reader, alg_buf) {
            out_header.alg = parse_jwt_alg(alg_buf[..]);
        } else {
            out_header.alg = JwtAlg.Unknown;
            had_error = true;
        }
    } else if key == "typ" {
        parse_jwt_header_str(reader, out_header.typ, seen_typ, had_error);
    } else if key == "kid" {
        parse_jwt_header_str(reader, out_header.kid, seen_kid, had_error);
    } else if key == "cty" {
        parse_jwt_header_str(reader, out_header.cty, seen_cty, had_error);
    } else if key == "crit" {
        if seen_crit { had_error = true; }
        seen_crit = true;
        let p = json::peek(reader);
        if p == '[' {
            parse_crit_header_elements(reader, out_header.crit, had_error);
        } else {
            json::skip(reader);
            had_error = true;
        }
    } else if key == "b64" {
        if out_header.has_b64 || is_header_key_present(key, seen_others[..]) {
            had_error = true;
        }
        let p = json::peek(reader);
        if p == 't' || p == 'f' {
            out_header.b64 = json::read_bool(reader);
            out_header.has_b64 = true;
            var item = SeenHeaderKey { .. };
            let _ = item.name.try_set("b64");
            if !seen_others.try_push(item) {
                had_error = true;
            }
        } else {
            json::skip(reader);
            had_error = true;
        }
    } else {
        if is_header_key_present(key, seen_others[..]) { had_error = true; }
        var item = SeenHeaderKey { .. };
        if !item.name.try_set(key) || !seen_others.try_push(item) {
            had_error = true;
        }
        json::skip(reader);
    }
}

// Parses a decoded JSON byte slice into a JwtHeader struct (RFC 7515 §4).
//
// Example:
//   json_bytes = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
//   returns: ok = true, out_header.alg = JwtAlg.HS256
fn parse_jwt_header_json(json_bytes: const u8[:], out_header: JwtHeader&) -> bool {
    guard json_bytes.validate_utf8() else {
        out_header = JwtHeader { .. };
        return false;
    }
    var reader = json::reader(json_bytes);
    out_header.kid.clear();
    out_header.cty.clear();
    out_header.typ.clear();
    out_header.crit.clear();
    out_header.b64 = true;
    out_header.has_b64 = false;
    var had_error = false;
    var seen_alg = false;
    var seen_typ = false;
    var seen_kid = false;
    var seen_cty = false;
    var seen_crit = false;
    var seen_others: SeenHeaderKey[..8] = [];

    json::each_member(reader) { key =>
        if key.contains('\\') {
            had_error = true;
            json::skip(reader);
        } else {
            parse_jwt_header_member(
                key, reader, out_header,
                seen_alg, seen_typ, seen_kid, seen_cty, seen_crit,
                seen_others, had_error,
            );
        }
    };

    // RFC 7515 §4.1.11: Every parameter listed in crit MUST be present in the header
    for &cp in out_header.crit {
        if !is_header_key_present(cp.name[..], seen_others[..]) {
            had_error = true;
        }
    }

    guard json::finish(reader) && !had_error && seen_alg else {
        out_header = JwtHeader { .. };
        return false;
    }
    return true;
}

// ---- JWT Claims Model & Parser -------------------------------------------

struct JwtClaimItem {
    key:      u8[..64]  = [],
    val_str:  u8[..256] = [],
    val_num:  i64       = 0,
    val_bool: bool      = false,
    is_num:   bool      = false,
    is_bool:  bool      = false,
}

struct JwtClaims {
    iss:           u8[..128]          = [],
    sub:           u8[..128]          = [],
    aud:           u8[..128]          = [],
    audiences:     u8[..128][..8]     = [],
    jti:           u8[..64]           = [],
    exp:           i64                = -1,
    nbf:           i64                = -1,
    iat:           i64                = -1,
    custom_claims: JwtClaimItem[..16] = [],
    raw_payload:   u8[..2048]         = [],
}

fn set_audience(claims: JwtClaims&, aud: const u8[:]) -> bool {
    var item: u8[..128] = [];
    guard aud.len > 0 && item.try_set(aud) && claims.aud.try_set(aud) else { return false; }
    claims.audiences.clear();
    return claims.audiences.try_push(item);
}

fn add_audience(claims: JwtClaims&, aud: const u8[:]) -> bool {
    var item: u8[..128] = [];
    guard aud.len > 0 && item.try_set(aud) && claims.audiences.try_push(item) else { return false; }
    if claims.aud.len == 0 {
        let _ = claims.aud.try_set(aud);
    }
    return true;
}

fn set_claim(claims: JwtClaims&, key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && !rfc::is_jwt_standard_claim_name(key) else { return false; }
    guard key.len <= 64 && val.len <= 256 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            let _ = c.val_str.try_set(val);
            c.val_num = 0;
            c.val_bool = false;
            c.is_num = false;
            c.is_bool = false;
            return true;
        }
    }
    var item = JwtClaimItem { .. };
    let _ = item.key.try_set(key);
    let _ = item.val_str.try_set(val);
    return claims.custom_claims.try_push(item);
}

fn set_claim_int(claims: JwtClaims&, key: const u8[:], val: i64) -> bool {
    guard key.len > 0 && !rfc::is_jwt_standard_claim_name(key) else { return false; }
    guard key.len <= 64 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_num = val;
            c.val_bool = false;
            c.is_num = true;
            c.is_bool = false;
            return true;
        }
    }
    var item = JwtClaimItem { val_num: val, is_num: true, .. };
    let _ = item.key.try_set(key);
    return claims.custom_claims.try_push(item);
}

fn set_claim_bool(claims: JwtClaims&, key: const u8[:], val: bool) -> bool {
    guard key.len > 0 && !rfc::is_jwt_standard_claim_name(key) else { return false; }
    guard key.len <= 64 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_num = 0;
            c.val_bool = val;
            c.is_bool = true;
            c.is_num = false;
            return true;
        }
    }
    var item = JwtClaimItem { val_bool: val, is_bool: true, .. };
    let _ = item.key.try_set(key);
    return claims.custom_claims.try_push(item);
}

fn claim_str(claims: const JwtClaims&, key: const u8[:]) -> const u8[:] {
    if key == "iss" {
        let s = claims.iss[..];
        return s;
    }
    if key == "sub" {
        let s = claims.sub[..];
        return s;
    }
    if key == "aud" {
        let s = claims.aud[..];
        return s;
    }
    if key == "jti" {
        let s = claims.jti[..];
        return s;
    }
    for &c in claims.custom_claims {
        if c.key[..] == key && !c.is_num && !c.is_bool {
            return c.val_str[..];
        }
    }
    return "";
}

fn claim_int(claims: const JwtClaims&, key: const u8[:]) -> i64, bool {
    if key == "exp" { return claims.exp, claims.exp >= 0; }
    if key == "nbf" { return claims.nbf, claims.nbf >= 0; }
    if key == "iat" { return claims.iat, claims.iat >= 0; }
    for &c in claims.custom_claims {
        if c.key[..] == key && c.is_num {
            return c.val_num, true;
        }
    }
    return 0, false;
}

fn claim_bool(claims: const JwtClaims&, key: const u8[:]) -> bool, bool {
    for &c in claims.custom_claims {
        if c.key[..] == key && c.is_bool {
            return c.val_bool, true;
        }
    }
    return false, false;
}

// Serializes audiences array in JSON format (RFC 7519 §4.1.3).
inline fn serialize_audiences_array<B>(audiences: const u8[..128][..8], out: B&) {
    out.push('[');
    for i in audiences.len {
        if i > 0 { out.push(','); }
        core::format_json_string(out, audiences[i][..]);
    }
    out.push(']');
}

// Serializes a single custom JWT claim item in JSON format.
inline fn serialize_custom_claim<B>(c: const JwtClaimItem&, out: B&) {
    core::format_json_key(out, c.key[..]);
    if c.is_num {
        c.val_num.format_i64_dec(out);
    } else if c.is_bool {
        out.append(if c.val_bool { "true" } else { "false" });
    } else {
        core::format_json_string(out, c.val_str[..]);
    }
}

fn serialize_jwt_claims<B>(claims: const JwtClaims&, out: B&) {
    out.push('{');
    var first = true;

    if claims.iss.len > 0 {
        core::format_json_key(out, "iss");
        core::format_json_string(out, claims.iss[..]);
        first = false;
    }
    if claims.sub.len > 0 {
        if !first { out.push(','); }
        core::format_json_key(out, "sub");
        core::format_json_string(out, claims.sub[..]);
        first = false;
    }
    if claims.audiences.len > 1 {
        if !first { out.push(','); }
        core::format_json_key(out, "aud");
        serialize_audiences_array(claims.audiences, out);
        first = false;
    } else if claims.aud.len > 0 {
        if !first { out.push(','); }
        core::format_json_key(out, "aud");
        core::format_json_string(out, claims.aud[..]);
        first = false;
    }
    if claims.jti.len > 0 {
        if !first { out.push(','); }
        core::format_json_key(out, "jti");
        core::format_json_string(out, claims.jti[..]);
        first = false;
    }
    if claims.exp >= 0 {
        if !first { out.push(','); }
        core::format_json_key(out, "exp");
        claims.exp.format_i64_dec(out);
        first = false;
    }
    if claims.nbf >= 0 {
        if !first { out.push(','); }
        core::format_json_key(out, "nbf");
        claims.nbf.format_i64_dec(out);
        first = false;
    }
    if claims.iat >= 0 {
        if !first { out.push(','); }
        core::format_json_key(out, "iat");
        claims.iat.format_i64_dec(out);
        first = false;
    }

    for &c in claims.custom_claims {
        if !first { out.push(','); }
        serialize_custom_claim(c, out);
        first = false;
    }

    out.push('}');
}

inline fn try_append_audience_element(
    reader:     json::Reader&,
    out_claims: JwtClaims&,
) -> bool {
    guard json::peek(reader) == '"' else {
        json::skip(reader);
        return false;
    }
    var item: u8[..128] = [];
    guard core::read_json_string_into(reader, item) && item.len > 0 &&
          out_claims.audiences.try_push(item) else {
        return false;
    }
    if out_claims.aud.len == 0 {
        let _ = out_claims.aud.try_set(item[..]);
    }
    return true;
}

// Parses aud claim from a JSON string or array (RFC 7519 §4.1.3).
//
// Example:
//   reader at "\"https://api.example.com\""
//   returns: out_claims.aud = "https://api.example.com", had_error = false
inline fn parse_aud_claim(
    reader:     json::Reader&,
    out_claims: JwtClaims&,
    had_error:  bool&,
) {
    let p = json::peek(reader);
    if p == '"' {
        var item: u8[..128] = [];
        let fits = core::read_json_string_into(reader, item) && item.len > 0;
        guard fits && out_claims.aud.try_set(item[..]) && out_claims.audiences.try_push(item) else {
            had_error = true;
            return;
        }
    } else if p == '[' {
        var count: i64 = 0;
        json::each_element(reader) {
            count = core::add_sat_i64(count, 1);
            if !try_append_audience_element(reader, out_claims) {
                had_error = true;
            }
        };
        if count == 0 {
            had_error = true; // RFC 7519 §4.1.3: aud array MUST NOT be empty
        }
    } else {
        json::skip(reader);
        had_error = true;
    }
}

// Parses a custom JWT claim into custom_claims list.
//
// Example:
//   key = "role", reader at "\"admin\""
//   returns: out_claims.custom_claims includes ("role", "admin")
inline fn parse_custom_claim_entry(
    key:        const u8[:],
    reader:     json::Reader&,
    out_claims: JwtClaims&,
    had_error:  bool&,
) {
    for &c in out_claims.custom_claims {
        if c.key[..] == key {
            had_error = true;
        }
    }
    let p = json::peek(reader);
    if p == '"' {
        var item = JwtClaimItem { .. };
        let str_ok = core::read_json_string_into(reader, item.val_str);
        if !str_ok || !item.key.try_set(key) || !out_claims.custom_claims.try_push(item) {
            had_error = true;
        }
    } else if p == 't' || p == 'f' {
        var item = JwtClaimItem { val_bool: json::read_bool(reader), is_bool: true, .. };
        if !item.key.try_set(key) || !out_claims.custom_claims.try_push(item) {
            had_error = true;
        }
    } else if (p >= '0' && p <= '9') || p == '-' {
        var item = JwtClaimItem { val_num: json::read_int(reader), is_num: true, .. };
        if !item.key.try_set(key) || !out_claims.custom_claims.try_push(item) {
            had_error = true;
        }
    } else {
        json::skip(reader);
    }
}

struct SeenCustomKey {
    name: u8[..128] = [],
}

inline fn seen_custom_keys_contains(key: const u8[:], seen: const SeenCustomKey[..64]) -> bool {
    for &sc in seen {
        if sc.name[..] == key { return true; }
    }
    return false;
}

// Parses a standard JWT claim (iss, sub, aud, jti, exp, nbf, iat) from JSON reader.
//
// Example:
//   key = "sub", reader at "\"user_42\""
//   returns: true (handled), out_claims.sub = "user_42"
inline fn parse_jwt_standard_claim(
    key:        const u8[:],
    reader:     json::Reader&,
    out_claims: JwtClaims&,
    seen_iss:   bool&,
    seen_sub:   bool&,
    seen_aud:   bool&,
    seen_jti:   bool&,
    seen_exp:   bool&,
    seen_nbf:   bool&,
    seen_iat:   bool&,
    had_error:  bool&,
) -> bool {
    if key == "iss" {
        if seen_iss { had_error = true; }
        seen_iss = true;
        if !core::read_json_string_into(reader, out_claims.iss) { had_error = true; }
        return true;
    }
    if key == "sub" {
        if seen_sub { had_error = true; }
        seen_sub = true;
        if !core::read_json_string_into(reader, out_claims.sub) { had_error = true; }
        return true;
    }
    if key == "aud" {
        if seen_aud { had_error = true; }
        seen_aud = true;
        parse_aud_claim(reader, out_claims, had_error);
        return true;
    }
    if key == "jti" {
        if seen_jti { had_error = true; }
        seen_jti = true;
        if !core::read_json_string_into(reader, out_claims.jti) { had_error = true; }
        return true;
    }
    if key == "exp" {
        if seen_exp { had_error = true; }
        seen_exp = true;
        let p = json::peek(reader);
        if (p >= '0' && p <= '9') || p == '-' {
            let num = json::read_number(reader);
            if num >= 0.0 && num <= 9223372036854774784.0 { out_claims.exp = num as i64; } else { had_error = true; }
        } else { json::skip(reader); had_error = true; }
        return true;
    }
    if key == "nbf" {
        if seen_nbf { had_error = true; }
        seen_nbf = true;
        let p = json::peek(reader);
        if (p >= '0' && p <= '9') || p == '-' {
            let num = json::read_number(reader);
            if num >= 0.0 && num <= 9223372036854774784.0 { out_claims.nbf = num as i64; } else { had_error = true; }
        } else { json::skip(reader); had_error = true; }
        return true;
    }
    if key == "iat" {
        if seen_iat { had_error = true; }
        seen_iat = true;
        let p = json::peek(reader);
        if (p >= '0' && p <= '9') || p == '-' {
            let num = json::read_number(reader);
            if num >= 0.0 && num <= 9223372036854774784.0 { out_claims.iat = num as i64; } else { had_error = true; }
        } else { json::skip(reader); had_error = true; }
        return true;
    }
    return false;
}

inline fn record_custom_claim(
    key:         const u8[:],
    reader:      json::Reader&,
    out_claims:  JwtClaims&,
    seen_custom: SeenCustomKey[..64]&,
    had_error:   bool&,
) {
    if seen_custom_keys_contains(key, seen_custom) {
        had_error = true;
    }
    var item = SeenCustomKey { .. };
    if !item.name.try_set(key) || !seen_custom.try_push(item) {
        had_error = true;
    }
    parse_custom_claim_entry(key, reader, out_claims, had_error);
}

// Parses a decoded JSON byte slice into a JwtClaims struct (RFC 7519 §4).
//
// Example:
//   json_bytes = "{\"sub\":\"user123\",\"exp\":1700000000}"
//   returns: ok = true, out_claims.sub = "user123"
fn parse_jwt_claims_json(json_bytes: const u8[:], out_claims: JwtClaims&) -> bool {
    guard json_bytes.validate_utf8() && out_claims.raw_payload.try_set(json_bytes) else {
        out_claims = JwtClaims { .. };
        return false;
    }
    var reader = json::reader(json_bytes);
    out_claims.iss.clear();
    out_claims.sub.clear();
    out_claims.aud.clear();
    out_claims.audiences.clear();
    out_claims.jti.clear();
    out_claims.exp = -1;
    out_claims.nbf = -1;
    out_claims.iat = -1;
    out_claims.custom_claims.clear();
    var had_error = false;

    var seen_iss = false;
    var seen_sub = false;
    var seen_aud = false;
    var seen_jti = false;
    var seen_exp = false;
    var seen_nbf = false;
    var seen_iat = false;
    var seen_custom: SeenCustomKey[..64] = [];

    json::each_member(reader) { key =>
        if key.contains('\\') {
            had_error = true;
            json::skip(reader);
        } else {
            let handled = parse_jwt_standard_claim(
                key, reader, out_claims,
                seen_iss, seen_sub, seen_aud, seen_jti, seen_exp, seen_nbf, seen_iat,
                had_error,
            );
            if !handled {
                record_custom_claim(key, reader, out_claims, seen_custom, had_error);
            }
        }
    };
    guard json::finish(reader) && !had_error else {
        out_claims = JwtClaims { .. };
        return false;
    }
    return true;
}

// ---- JWT Validation Options ----------------------------------------------

struct JwtValidationOptions {
    expected_alg:              JwtAlg         = JwtAlg.HS256,
    expected_issuer:           u8[..128]      = [],
    expected_audience:         u8[..128]      = [],
    expected_subject:          u8[..128]      = [],
    expected_typ:              u8[..32]       = [],  // RFC 8725 §3.11 & RFC 9068: Explicit type verification
    supported_crit:            CritParam[..8] = [],  // RFC 7515 §4.1.11 / RFC 8725 §3.8: Supported critical parameters
    allowed_issuers:           u8[..128][..4] = [],
    allowed_audiences:         u8[..128][..4] = [],
    leeway_seconds:            i64            = DEFAULT_JWT_LEEWAY_SECONDS,
    min_remaining_ttl_seconds: i64            = 0,
    require_exp:               bool           = true,
    require_nbf:               bool           = false,
    allow_none_alg:            bool           = false,  // RFC 8725 §3.1: Strictly false by default
    validate_aud_when_present: bool           = false,  // RFC 7519 §4.1.3: Reject non-empty aud when unconfigured
}

fn default_jwt_validation_options(expected_alg: JwtAlg = JwtAlg.HS256) -> JwtValidationOptions {
    return JwtValidationOptions {
        expected_alg:   expected_alg,
        leeway_seconds: DEFAULT_JWT_LEEWAY_SECONDS,
        require_exp:    true,
        require_nbf:    false,
        allow_none_alg: false,
        ..
    };
}

fn add_supported_crit(opts: JwtValidationOptions&, name: const u8[:]) -> bool {
    guard name.len > 0 && !rfc::is_standard_jws_header_param(name) else { return false; }
    for &cp in opts.supported_crit {
        guard cp.name[..] != name else { return false; }
    }
    var item = CritParam { .. };
    return item.name.try_set(name) && opts.supported_crit.try_push(item);
}

// ---- JWS Signing Pipeline (HMAC & Ed25519) -------------------------------

// Serializes Header and Claims into Base64URL-encoded signing input: `<hdr_b64>.<clm_b64>`
fn build_jwt_signing_input<B>(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    out_token: B&,
) {
    var hdr_json: u8[..1024] = [];
    serialize_jwt_header(header, hdr_json);
    core::base64url_encode(hdr_json[..], out_token);
    out_token.push('.');

    var clm_json: u8[..4096] = [];
    serialize_jwt_claims(claims, clm_json);
    core::base64url_encode(clm_json[..], out_token);
}

fn append_jwt_hmac_signature<B>(
    alg:           JwtAlg,
    secret_key:    const u8[:],
    signing_input: const u8[:],
    out_token:     B&,
) {
    out_token.push('.');
    if alg == JwtAlg.HS256 {
        let mac256 = core::hmac_sha256(secret_key, signing_input);
        core::base64url_encode(mac256[..], out_token);
    } else if alg == JwtAlg.HS384 {
        let mac384 = core::hmac_sha384(secret_key, signing_input);
        core::base64url_encode(mac384[..], out_token);
    } else if alg == JwtAlg.HS512 {
        let mac512 = core::hmac_sha512(secret_key, signing_input);
        core::base64url_encode(mac512[..], out_token);
    }
}

// Signs a JWT using symmetric HMAC (HS256, HS384, HS512 per RFC 7518)
fn sign_jwt_hmac<B>(
    header:     const JwtHeader&,
    claims:     const JwtClaims&,
    secret_key: const u8[:],
    out_token:  B&,
) -> bool {
    guard header.alg == JwtAlg.HS256 || header.alg == JwtAlg.HS384 || header.alg == JwtAlg.HS512 else {
        return false;
    }
    guard secret_key.len >= 16 else { return false; }
    out_token.clear();

    var token_buf: u8[..8192] = [];
    build_jwt_signing_input(header, claims, token_buf);
    let signing_input = token_buf[..];
    append_jwt_hmac_signature(header.alg, secret_key, signing_input, token_buf);
    return out_token.try_set(token_buf[..]);
}

fn sign_jwt_hmac(
    header:     const JwtHeader&,
    claims:     const JwtClaims&,
    secret_key: const u8[:],
    out_token:  u8[>..]&,
) -> bool {
    guard header.alg == JwtAlg.HS256 || header.alg == JwtAlg.HS384 || header.alg == JwtAlg.HS512 else {
        return false;
    }
    guard secret_key.len >= 16 else { return false; }
    out_token.clear();
    build_jwt_signing_input(header, claims, out_token);
    let signing_input = out_token[..];
    append_jwt_hmac_signature(header.alg, secret_key, signing_input, out_token);
    return true;
}

fn append_jwt_eddsa_signature<B>(
    seed_key:      const u8[32],
    signing_input: const u8[:],
    out_token:     B&,
) {
    let sig64 = core::ed25519_sign(seed_key, signing_input);
    out_token.push('.');
    core::base64url_encode(sig64[..], out_token);
}

// Signs a JWT using asymmetric Ed25519 (EdDSA per RFC 8037)
fn sign_jwt_eddsa<B>(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    seed_key:  const u8[32],
    out_token: B&,
) -> bool {
    guard header.alg == JwtAlg.EdDSA else { return false; }
    out_token.clear();

    var token_buf: u8[..8192] = [];
    build_jwt_signing_input(header, claims, token_buf);
    let signing_input = token_buf[..];
    append_jwt_eddsa_signature(seed_key, signing_input, token_buf);
    return out_token.try_set(token_buf[..]);
}

fn sign_jwt_eddsa(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    seed_key:  const u8[32],
    out_token: u8[>..]&,
) -> bool {
    guard header.alg == JwtAlg.EdDSA else { return false; }
    out_token.clear();
    build_jwt_signing_input(header, claims, out_token);
    let signing_input = out_token[..];
    append_jwt_eddsa_signature(seed_key, signing_input, out_token);
    return true;
}

// Signs a JWT using asymmetric ECDSA P-256 (ES256 per RFC 7518 §3.4).
fn sign_jwt_es256<B>(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    priv_key:  const u8[32],
    out_token: B&,
) -> bool {
    guard header.alg == JwtAlg.ES256 else { return false; }
    out_token.clear();

    var token_buf: u8[..8192] = [];
    build_jwt_signing_input(header, claims, token_buf);
    let signing_input = token_buf[..];
    let sig64 = core::ecdsa_p256_sign(priv_key, signing_input);
    token_buf.push('.');
    core::base64url_encode(sig64[..], token_buf);
    return out_token.try_set(token_buf[..]);
}

fn sign_jwt_es256(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    priv_key:  const u8[32],
    out_token: u8[>..]&,
) -> bool {
    guard header.alg == JwtAlg.ES256 else { return false; }
    out_token.clear();
    build_jwt_signing_input(header, claims, out_token);
    let sig64 = core::ecdsa_p256_sign(priv_key, out_token[..]);
    out_token.push('.');
    core::base64url_encode(sig64[..], out_token);
    return true;
}

// Signs a JWT using asymmetric RSASSA-PKCS1-v1_5 SHA-256 (RS256 per RFC 7518 §3.3).
fn sign_jwt_rs256<B>(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    n_be:      const u8[:],
    d_be:      const u8[:],
    out_token: B&,
) -> bool {
    guard header.alg == JwtAlg.RS256 && n_be.len >= 256 && n_be.len <= 512 else { return false; }
    out_token.clear();

    var token_buf: u8[..8192] = [];
    build_jwt_signing_input(header, claims, token_buf);
    var sig_buf: u8[..512] = [];
    guard core::rsa_pkcs1_sha256_sign(n_be, d_be, token_buf[..], sig_buf) else { return false; }
    token_buf.push('.');
    core::base64url_encode(sig_buf[..], token_buf);
    return out_token.try_set(token_buf[..]);
}

fn sign_jwt_rs256(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    n_be:      const u8[:],
    d_be:      const u8[:],
    out_token: u8[>..]&,
) -> bool {
    guard header.alg == JwtAlg.RS256 && n_be.len >= 256 && n_be.len <= 512 else { return false; }
    out_token.clear();
    build_jwt_signing_input(header, claims, out_token);
    var sig_buf: u8[..512] = [];
    guard core::rsa_pkcs1_sha256_sign(n_be, d_be, out_token[..], sig_buf) else { return false; }
    out_token.push('.');
    core::base64url_encode(sig_buf[..], out_token);
    return true;
}

// Signs a JWT using asymmetric RSASSA-PSS SHA-256 (PS256 per RFC 7518 §3.5).
fn sign_jwt_ps256<B>(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    n_be:      const u8[:],
    d_be:      const u8[:],
    salt:      const u8[:],
    out_token: B&,
) -> bool {
    guard header.alg == JwtAlg.PS256 && n_be.len >= 256 && n_be.len <= 512 else { return false; }
    out_token.clear();

    var token_buf: u8[..8192] = [];
    build_jwt_signing_input(header, claims, token_buf);
    var sig_buf: u8[..512] = [];
    guard core::rsa_pss_sha256_sign(n_be, d_be, salt, token_buf[..], sig_buf) else { return false; }
    token_buf.push('.');
    core::base64url_encode(sig_buf[..], token_buf);
    return out_token.try_set(token_buf[..]);
}

fn sign_jwt_ps256(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    n_be:      const u8[:],
    d_be:      const u8[:],
    salt:      const u8[:],
    out_token: u8[>..]&,
) -> bool {
    guard header.alg == JwtAlg.PS256 && n_be.len >= 256 && n_be.len <= 512 else { return false; }
    out_token.clear();
    build_jwt_signing_input(header, claims, out_token);
    var sig_buf: u8[..512] = [];
    guard core::rsa_pss_sha256_sign(n_be, d_be, salt, out_token[..], sig_buf) else { return false; }
    out_token.push('.');
    core::base64url_encode(sig_buf[..], out_token);
    return true;
}

// ---- JWT Verification & Claim Validation ---------------------------------

// Hard bounds on raw token and component sizes to prevent parser DoS and memory exhaustion
const MAX_JWT_TOKEN_LEN:       i64 = 8192;
const MAX_JWT_HEADER_PART_LEN: i64 = 1365;
const MAX_JWT_CLAIMS_PART_LEN: i64 = 2730;

fn split_jwt_parts(
    token: const u8[:],
    dot1:  i64&,
    dot2:  i64&,
) -> bool {
    guard token.len > 0 && token.len <= MAX_JWT_TOKEN_LEN else { return false; }
    dot1 = -1;
    dot2 = -1;
    for i in token.len {
        if token[i] == '.' {
            if dot1 == -1 {
                dot1 = i;
            } else if dot2 == -1 {
                dot2 = i;
            } else {
                return false; // RFC 7519 §3: exactly two dots
            }
        }
    }
    guard dot1 > 0 && dot1 <= MAX_JWT_HEADER_PART_LEN else { return false; }
    let claims_len = core::sub_sat_i64(dot2, dot1);
    guard claims_len > 1 && claims_len <= MAX_JWT_CLAIMS_PART_LEN else { return false; }
    return true;
}

fn validate_jwt_expiration(exp: i64, require_exp: bool, leeway: i64, now_unix_sec: i64) -> bool {
    guard leeway >= 0 && now_unix_sec >= 0 && exp >= -1 else { return false; }
    if exp >= 0 {
        let max_exp_cutoff = core::add_sat_i64(exp, leeway);
        return now_unix_sec < max_exp_cutoff;
    }
    return !require_exp;
}

fn validate_jwt_not_before(nbf: i64, require_nbf: bool, leeway: i64, now_unix_sec: i64) -> bool {
    guard leeway >= 0 && now_unix_sec >= 0 && nbf >= -1 else { return false; }
    if nbf >= 0 {
        let min_nbf_cutoff = max(0, core::sub_sat_i64(nbf, leeway));
        return now_unix_sec >= min_nbf_cutoff;
    }
    return !require_nbf;
}

inline fn claims_match_audience(claims: const JwtClaims&, expected: const u8[:]) -> bool {
    if claims.aud.len > 0 && claims.aud[..] == expected { return true; }
    for &a in claims.audiences {
        if a[..] == expected { return true; }
    }
    return false;
}

inline fn claims_match_issuer_allowlist(claims: const JwtClaims&, options: const JwtValidationOptions&) -> bool {
    guard claims.iss.len > 0 else { return false; }
    for &allowed in options.allowed_issuers {
        if allowed.len > 0 && claims.iss[..] == allowed[..] { return true; }
    }
    return false;
}

inline fn claims_match_audience_allowlist(claims: const JwtClaims&, options: const JwtValidationOptions&) -> bool {
    for &allowed in options.allowed_audiences {
        if allowed.len > 0 && claims_match_audience(claims, allowed[..]) { return true; }
    }
    return false;
}

fn validate_jwt_identity_claims(claims: const JwtClaims&, options: const JwtValidationOptions&) -> JwtError {
    if options.expected_issuer.len > 0 && claims.iss[..] != options.expected_issuer[..] {
        return JwtError.IssuerMismatch;
    }
    if options.expected_issuer.len == 0 && options.allowed_issuers.len > 0 {
        if !claims_match_issuer_allowlist(claims, options) {
            return JwtError.IssuerMismatch;
        }
    }
    if options.expected_audience.len > 0 && !claims_match_audience(claims, options.expected_audience[..]) {
        return JwtError.AudienceMismatch;
    }
    if options.expected_audience.len == 0 && options.allowed_audiences.len > 0 {
        if !claims_match_audience_allowlist(claims, options) {
            return JwtError.AudienceMismatch;
        }
    }
    if options.validate_aud_when_present && (claims.aud.len > 0 || claims.audiences.len > 0) {
        if options.expected_audience.len == 0 && options.allowed_audiences.len == 0 {
            return JwtError.AudienceMismatch;
        }
    }
    if options.expected_subject.len > 0 && claims.sub[..] != options.expected_subject[..] {
        return JwtError.SubjectMismatch;
    }
    return JwtError.None;
}

// Validates time and identity claims against options
fn validate_jwt_claims_rules(
    claims:       const JwtClaims&,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
) -> JwtError {
    if !validate_jwt_expiration(claims.exp, options.require_exp, options.leeway_seconds, now_unix_sec) {
        return JwtError.TokenExpired;
    }
    if options.min_remaining_ttl_seconds > 0 && claims.exp >= 0 {
        if core::sub_sat_i64(claims.exp, options.min_remaining_ttl_seconds) < now_unix_sec {
            return JwtError.TokenExpired;
        }
    }
    if !validate_jwt_not_before(claims.nbf, options.require_nbf, options.leeway_seconds, now_unix_sec) {
        return JwtError.TokenNotYetValid;
    }
    return validate_jwt_identity_claims(claims, options);
}

// Decodes and parses a base64url-encoded JWT header into a JwtHeader struct.
//
// Example:
//   hdr_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
//   returns: JwtError.None, out_header.alg = JwtAlg.HS256
fn decode_jwt_header(hdr_b64: const u8[:], out_header: JwtHeader&) -> JwtError {
    var hdr_json: u8[..1024] = [];
    guard hdr_b64.len > 0 && hdr_b64.index_of_byte('=') == -1 &&
          core::base64url_decode(hdr_b64, hdr_json) else {
        out_header = JwtHeader { .. };
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_header_json(hdr_json[..], out_header) else {
        return JwtError.InvalidHeaderJson;
    }
    return JwtError.None;
}

// Decodes and parses a base64url-encoded JWT claims payload into a JwtClaims struct.
//
// Example:
//   clm_b64 = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
//   returns: JwtError.None, out_claims.sub = "1234567890"
fn decode_jwt_claims(clm_b64: const u8[:], out_claims: JwtClaims&) -> JwtError {
    var clm_json: u8[..4096] = [];
    guard clm_b64.len > 0 && clm_b64.index_of_byte('=') == -1 &&
          core::base64url_decode(clm_b64, clm_json) else {
        out_claims = JwtClaims { .. };
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_claims_json(clm_json[..], out_claims) else {
        return JwtError.InvalidClaimsJson;
    }
    return JwtError.None;
}

// Decodes and parses header only without signature verification (RFC 7519).
//
// Example:
//   token = "eyJhbGciOiJIUzI1NiJ9.e30.sig"
//   returns: JwtError.None, out_header.alg = JwtAlg.HS256
fn parse_jwt_header_only(
    token:      const u8[:],
    out_header: JwtHeader&,
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) && token.index_of_byte('=') == -1 else {
        return JwtError.MalformedToken;
    }
    return decode_jwt_header(token[..dot1], out_header);
}

// Decodes and parses header and claims without signature verification (RFC 7519).
//
// Example:
//   token = "header_b64.claims_b64.signature_b64"
//   returns: JwtError.None, out_header and out_claims populated
fn parse_jwt_unverified(
    token:      const u8[:],
    out_header: JwtHeader&,
    out_claims: JwtClaims&,
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) && token.index_of_byte('=') == -1 else {
        return JwtError.MalformedToken;
    }

    var temp_header = JwtHeader { .. };
    let hdr_err = decode_jwt_header(token[..dot1], temp_header);
    guard hdr_err == JwtError.None else { return hdr_err; }
    if temp_header.has_b64 && !temp_header.b64 {
        return JwtError.CriticalHeaderUnsupported;
    }

    let sig_start = core::add_sat_i64(dot2, 1);
    let sig_part = token[sig_start..];
    if temp_header.alg == JwtAlg.None {
        guard sig_part.len == 0 else { return JwtError.MalformedToken; }
    } else {
        var sig_buf: u8[..512] = [];
        guard sig_part.len > 0 && core::base64url_decode(sig_part, sig_buf) else {
            return JwtError.InvalidBase64;
        }
    }

    var temp_claims = JwtClaims { .. };
    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], temp_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    out_header = copy(temp_header);
    out_claims = copy(temp_claims);
    return JwtError.None;
}

fn verify_jwt_algorithm(header_alg: JwtAlg, expected_alg: JwtAlg, allow_none: bool) -> JwtError {
    if header_alg == JwtAlg.Unknown {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.None {
        return if allow_none { JwtError.None } else { JwtError.UnsupportedAlgorithm };
    }
    if header_alg != expected_alg {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}

fn is_matching_jwt_typ(header_typ: const u8[:], expected_typ: const u8[:]) -> bool {
    guard header_typ.len > 0 && expected_typ.len > 0 else { return false; }
    if header_typ.eq_ascii_fold(expected_typ) {
        return true;
    }
    // Handle "application/" media type prefix equivalence when no other '/' appears (RFC 7515 §4.1.9 / RFC 8725 §3.11)
    if expected_typ.starts_with_fold("application/") && !expected_typ[12..].contains_byte('/') {
        if header_typ.eq_ascii_fold(expected_typ[12..]) {
            return true;
        }
    }
    if header_typ.starts_with_fold("application/") && !header_typ[12..].contains_byte('/') {
        if header_typ[12..].eq_ascii_fold(expected_typ) {
            return true;
        }
    }
    return false;
}

inline fn is_crit_param_supported(cp_name: const u8[:], supported: const CritParam[..8]) -> bool {
    if cp_name == "b64" { return true; }
    for &sc in supported {
        if sc.name[..] == cp_name { return true; }
    }
    return false;
}

inline fn has_crit_param_in_header(header: const JwtHeader&, name: const u8[:]) -> bool {
    for &cp in header.crit {
        if cp.name[..] == name { return true; }
    }
    return false;
}

fn verify_jwt_header_rules(header: const JwtHeader&, options: const JwtValidationOptions&) -> JwtError {
    let alg_err = verify_jwt_algorithm(header.alg, options.expected_alg, options.allow_none_alg);
    guard alg_err == JwtError.None else { return alg_err; }

    // RFC 8725 §3.11 & RFC 9068: Explicit JWT typ verification
    if options.expected_typ.len > 0 {
        if !is_matching_jwt_typ(header.typ[..], options.expected_typ[..]) {
            return JwtError.TypeMismatch;
        }
    }

    // RFC 7797 §7: JWTs MUST NOT use the JWS Unencoded Payload Option ("b64": false)
    if header.has_b64 && !header.b64 {
        return JwtError.CriticalHeaderUnsupported;
    }

    // RFC 7515 §4.1.11 / RFC 8725 §3.8: Critical Header Parameters (crit)
    if header.crit.len > 0 {
        for &cp in header.crit {
            if !is_crit_param_supported(cp.name[..], options.supported_crit) {
                return JwtError.CriticalHeaderUnsupported;
            }
        }
    }

    return JwtError.None;
}

fn verify_jwt_hmac_signature(
    alg:           JwtAlg,
    secret_key:    const u8[:],
    signing_input: const u8[:],
    sig_bytes:     const u8[:],
) -> bool {
    if alg == JwtAlg.HS256 {
        guard sig_bytes.len == rfc::HMAC_SHA256_MAC_LEN else { return false; }
        let expected = core::hmac_sha256(secret_key, signing_input);
        return core::ct_eq_bytes(expected[..], sig_bytes);
    } else if alg == JwtAlg.HS384 {
        guard sig_bytes.len == rfc::HMAC_SHA384_MAC_LEN else { return false; }
        let expected = core::hmac_sha384(secret_key, signing_input);
        return core::ct_eq_bytes(expected[..], sig_bytes);
    } else if alg == JwtAlg.HS512 {
        guard sig_bytes.len == rfc::HMAC_SHA512_MAC_LEN else { return false; }
        let expected = core::hmac_sha512(secret_key, signing_input);
        return core::ct_eq_bytes(expected[..], sig_bytes);
    }
    return false;
}

// Verifies a JWT signed with HMAC (HS256, HS384, HS512)
fn verify_jwt_hmac(
    token:        const u8[:],
    secret_key:   const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    guard secret_key.len >= 16 else {
        return JwtError.SignatureInvalid;
    }

    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }
    guard token.index_of_byte('=') == -1 else {
        return JwtError.MalformedToken;
    }

    var temp_header = JwtHeader { .. };
    let hdr_err = decode_jwt_header(token[..dot1], temp_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let hdr_rule_err = verify_jwt_header_rules(temp_header, options);
    guard hdr_rule_err == JwtError.None else { return hdr_rule_err; }

    if temp_header.alg != JwtAlg.HS256 && temp_header.alg != JwtAlg.HS384 && temp_header.alg != JwtAlg.HS512 {
        return JwtError.AlgorithmMismatch;
    }

    var sig_bytes: u8[..128] = [];
    let sig_start = core::add_sat_i64(dot2, 1);
    guard core::sub_sat_i64(token.len, sig_start) <= 172 else {
        return JwtError.SignatureInvalid;
    }
    guard core::base64url_decode(token[sig_start..], sig_bytes) else {
        return JwtError.InvalidBase64;
    }

    let signing_input = token[..dot2];
    guard verify_jwt_hmac_signature(temp_header.alg, secret_key, signing_input, sig_bytes[..]) else {
        return JwtError.SignatureInvalid;
    }

    var temp_claims = JwtClaims { .. };
    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], temp_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    let clm_rule_err = validate_jwt_claims_rules(temp_claims, options, now_unix_sec);
    guard clm_rule_err == JwtError.None else { return clm_rule_err; }

    out_header = copy(temp_header);
    out_claims = copy(temp_claims);
    return JwtError.None;
}

fn verify_jwt_eddsa_signature(
    public_key:    const u8[32],
    signing_input: const u8[:],
    sig_bytes:     const u8[:],
) -> bool {
    guard sig_bytes.len == rfc::ED25519_SIG_LEN else { return false; }
    var sig64: u8[64] = [0; 64];
    for i in rfc::ED25519_SIG_LEN {
        sig64[i] = sig_bytes[i];
    }
    return core::ed25519_verify(public_key, signing_input, sig64);
}

// Verifies a JWT signed with Ed25519 (EdDSA)
fn verify_jwt_eddsa(
    token:        const u8[:],
    public_key:   const u8[32],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }
    guard token.index_of_byte('=') == -1 else {
        return JwtError.MalformedToken;
    }

    var temp_header = JwtHeader { .. };
    let hdr_err = decode_jwt_header(token[..dot1], temp_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let hdr_rule_err = verify_jwt_header_rules(temp_header, options);
    guard hdr_rule_err == JwtError.None else { return hdr_rule_err; }

    if temp_header.alg != JwtAlg.EdDSA {
        return JwtError.AlgorithmMismatch;
    }

    var sig_bytes: u8[..128] = [];
    let sig_start = core::add_sat_i64(dot2, 1);
    guard core::sub_sat_i64(token.len, sig_start) <= 172 else {
        return JwtError.SignatureInvalid;
    }
    guard core::base64url_decode(token[sig_start..], sig_bytes) else {
        return JwtError.InvalidBase64;
    }

    let signing_input = token[..dot2];
    guard verify_jwt_eddsa_signature(public_key, signing_input, sig_bytes[..]) else {
        return JwtError.SignatureInvalid;
    }

    var temp_claims = JwtClaims { .. };
    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], temp_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    let clm_rule_err = validate_jwt_claims_rules(temp_claims, options, now_unix_sec);
    guard clm_rule_err == JwtError.None else { return clm_rule_err; }

    out_header = copy(temp_header);
    out_claims = copy(temp_claims);
    return JwtError.None;
}

// Verifies a JWT signed with ECDSA P-256 (ES256 per RFC 7518 §3.4).
fn verify_jwt_es256(
    token:        const u8[:],
    public_key:   const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }
    guard token.index_of_byte('=') == -1 else {
        return JwtError.MalformedToken;
    }

    var temp_header = JwtHeader { .. };
    let hdr_err = decode_jwt_header(token[..dot1], temp_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let hdr_rule_err = verify_jwt_header_rules(temp_header, options);
    guard hdr_rule_err == JwtError.None else { return hdr_rule_err; }

    if temp_header.alg != JwtAlg.ES256 {
        return JwtError.AlgorithmMismatch;
    }

    var sig_bytes: u8[..128] = [];
    let sig_start = core::add_sat_i64(dot2, 1);
    guard core::sub_sat_i64(token.len, sig_start) <= 172 else {
        return JwtError.SignatureInvalid;
    }
    guard core::base64url_decode(token[sig_start..], sig_bytes) else {
        return JwtError.InvalidBase64;
    }
    // RFC 7518 §3.4: ES256 JWS signature MUST be the 64-octet R || S representation
    guard sig_bytes.len == 64 else {
        return JwtError.SignatureInvalid;
    }

    let signing_input = token[..dot2];
    guard core::ecdsa_p256_verify(public_key, signing_input, sig_bytes[..]) else {
        return JwtError.SignatureInvalid;
    }

    var temp_claims = JwtClaims { .. };
    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], temp_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    let clm_rule_err = validate_jwt_claims_rules(temp_claims, options, now_unix_sec);
    guard clm_rule_err == JwtError.None else { return clm_rule_err; }

    out_header = copy(temp_header);
    out_claims = copy(temp_claims);
    return JwtError.None;
}

fn verify_jwt_rsa_signature(
    alg:           JwtAlg,
    n_be:          const u8[:],
    e_be:          const u8[:],
    signing_input: const u8[:],
    sig_bytes:     const u8[:],
) -> bool {
    guard n_be.len >= 256 && n_be.len <= 512 && e_be.len >= 1 && e_be.len <= 8 else { return false; }
    let n_last = core::sub_sat_i64(n_be.len, 1);
    guard (n_be[0] & 0x80) != 0 && (n_be[n_last] & 1) == 1 else { return false; }
    guard e_be[0] != 0 && core::is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    if alg == JwtAlg.RS256 {
        return core::rsa_pkcs1_sha256_verify(n_be, e_be, signing_input, sig_bytes);
    } else if alg == JwtAlg.PS256 {
        return core::rsa_pss_sha256_verify(n_be, e_be, signing_input, sig_bytes);
    }
    return false;
}

// Verifies a JWT signed with RSA (RS256 or PS256 per RFC 7518 §3.3, §3.5).
fn verify_jwt_rsa(
    token:        const u8[:],
    n_be:         const u8[:],
    e_be:         const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }
    guard token.index_of_byte('=') == -1 else {
        return JwtError.MalformedToken;
    }

    var temp_header = JwtHeader { .. };
    let hdr_err = decode_jwt_header(token[..dot1], temp_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let hdr_rule_err = verify_jwt_header_rules(temp_header, options);
    guard hdr_rule_err == JwtError.None else { return hdr_rule_err; }

    if temp_header.alg != JwtAlg.RS256 && temp_header.alg != JwtAlg.PS256 {
        return JwtError.AlgorithmMismatch;
    }

    var sig_bytes: u8[..512] = [];
    let sig_start = core::add_sat_i64(dot2, 1);
    guard core::sub_sat_i64(token.len, sig_start) <= 684 else {
        return JwtError.SignatureInvalid;
    }
    guard core::base64url_decode(token[sig_start..], sig_bytes) else {
        return JwtError.InvalidBase64;
    }

    let signing_input = token[..dot2];
    guard verify_jwt_rsa_signature(temp_header.alg, n_be, e_be, signing_input, sig_bytes[..]) else {
        return JwtError.SignatureInvalid;
    }

    var temp_claims = JwtClaims { .. };
    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], temp_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    let clm_rule_err = validate_jwt_claims_rules(temp_claims, options, now_unix_sec);
    guard clm_rule_err == JwtError.None else { return clm_rule_err; }

    out_header = copy(temp_header);
    out_claims = copy(temp_claims);
    return JwtError.None;
}

// Verifies an RFC 7797 JWS Compact Serialization with unencoded payload ("b64": false) using HS256.
// Locates the signature after the last '.' and verifies over `header_b64 || '.' || raw_payload`.
fn verify_jws_unencoded_hs256(compact_token: const u8[:], secret: const u8[:]) -> bool {
    guard secret.len >= 16 && compact_token.len > 0 && compact_token.len <= MAX_JWT_TOKEN_LEN else {
        return false;
    }
    let dot1 = compact_token.index_of_byte('.');
    let last_dot = compact_token.last_index_of_byte('.');
    guard dot1 > 0 && dot1 <= MAX_JWT_HEADER_PART_LEN && last_dot > dot1 else {
        return false;
    }
    let hdr_b64 = compact_token[..dot1];
    let sig_start = core::add_sat_i64(last_dot, 1);
    let sig_b64 = compact_token[sig_start..];
    guard hdr_b64.index_of_byte('=') == -1 && sig_b64.index_of_byte('=') == -1 else {
        return false;
    }
    var hdr = JwtHeader { .. };
    guard decode_jwt_header(hdr_b64, hdr) == JwtError.None else { return false; }
    guard hdr.alg == JwtAlg.HS256 && hdr.has_b64 && !hdr.b64 else { return false; }
    guard has_crit_param_in_header(hdr, "b64") else { return false; }
    for &cp in hdr.crit {
        if cp.name[..] != "b64" { return false; }
    }
    var sig_bytes: u8[..128] = [];
    guard sig_b64.len <= 172 && core::base64url_decode(sig_b64, sig_bytes) else {
        return false;
    }
    let signing_input = compact_token[..last_dot];
    return verify_jwt_hmac_signature(JwtAlg.HS256, secret, signing_input, sig_bytes[..]);
}
