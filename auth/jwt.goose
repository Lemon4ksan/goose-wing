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
    if s == "none" { return JwtAlg.None; }
    return JwtAlg.Unknown;
}

enum JwtError {
    None,
    MalformedToken,        // Missing dots, wrong part count (must be exactly 3 parts)
    InvalidBase64,         // Base64URL decoding failed
    InvalidHeaderJson,     // Header JSON could not be parsed
    InvalidClaimsJson,     // Claims JSON could not be parsed
    UnsupportedAlgorithm,  // Unknown algorithm or 'none' when not explicitly allowed
    AlgorithmMismatch,     // Token header alg does not match expected verification alg
    SignatureInvalid,      // Cryptographic signature check failed
    TokenExpired,          // exp claim is before now - leeway
    TokenNotYetValid,      // nbf claim is after now + leeway
    IssuerMismatch,        // iss claim does not match expected issuer
    AudienceMismatch,      // aud claim does not match expected audience
    SubjectMismatch,       // sub claim does not match expected subject
    KeyNotFound,           // kid requested by token not found in JWKS
    CriticalHeaderUnsupported, // crit header contains unsupported param (RFC 7515 §4.1.11 / RFC 8725 §3.8)
    TypeMismatch,          // typ header does not match expected type (RFC 8725 §3.11 / RFC 9068)
}

fn jwt_error_to_string(err: JwtError) -> const u8[:] {
    return match err {
        None => "none",
        MalformedToken => "malformed token structure",
        InvalidBase64 => "invalid base64url encoding",
        InvalidHeaderJson => "invalid header json",
        InvalidClaimsJson => "invalid claims json",
        UnsupportedAlgorithm => "unsupported signature algorithm",
        AlgorithmMismatch => "algorithm mismatch (algorithm confusion defense)",
        SignatureInvalid => "cryptographic signature invalid",
        TokenExpired => "token expired (exp)",
        TokenNotYetValid => "token not yet valid (nbf)",
        IssuerMismatch => "issuer mismatch (iss)",
        AudienceMismatch => "audience mismatch (aud)",
        SubjectMismatch => "subject mismatch (sub)",
        KeyNotFound => "key id (kid) not found in jwks",
        CriticalHeaderUnsupported => "unsupported critical header parameter (crit)",
        TypeMismatch => "token type mismatch (typ confusion defense)",
    };
}

// ---- JWT Header Model & Parser -------------------------------------------

struct CritParam {
    name: u8[..32] = [],
}

struct JwtHeader {
    alg:  JwtAlg         = JwtAlg.HS256,
    typ:  u8[..32]       = "JWT",
    kid:  u8[..64]       = [],
    cty:  u8[..32]       = [],
    crit: CritParam[..8] = [],
}

fn new_jwt_header(alg: JwtAlg = JwtAlg.HS256, kid: const u8[:] = "") -> JwtHeader {
    var hdr = JwtHeader {
        alg: alg,
        ..
    };
    if kid.len > 0 {
        hdr.kid.append(kid);
    }
    return hdr;
}

fn add_header_crit(header: JwtHeader&, name: const u8[:]) -> bool {
    guard header.crit.len < header.crit.cap && name.len <= 32 else { return false; }
    var item = CritParam { .. };
    item.name.append(name);
    header.crit.push(item);
    return true;
}

fn serialize_jwt_header<B>(header: const JwtHeader&, out: B&) {
    out.append("{\"alg\":");
    json::format_string(out, jwt_alg_to_string(header.alg));
    if header.typ.len > 0 {
        out.append(",\"typ\":");
        json::format_string(out, header.typ[..]);
    }
    if header.kid.len > 0 {
        out.append(",\"kid\":");
        json::format_string(out, header.kid[..]);
    }
    if header.cty.len > 0 {
        out.append(",\"cty\":");
        json::format_string(out, header.cty[..]);
    }
    if header.crit.len > 0 {
        out.append(",\"crit\":[");
        for i in header.crit.len {
            if i > 0 { out.push(','); }
            json::format_string(out, header.crit[i].name[..]);
        }
        out.push(']');
    }
    out.push('}');
}

fn is_standard_jws_header_param(name: const u8[:]) -> bool {
    return name == "alg" ||
           name == "jku" ||
           name == "jwk" ||
           name == "kid" ||
           name == "x5u" ||
           name == "x5c" ||
           name == "x5t" ||
           name == "x5t#S256" ||
           name == "typ" ||
           name == "cty" ||
           name == "crit";
}

struct SeenHeaderKey {
    name: u8[..64] = [],
}

// Parses critical header parameters from JSON array (RFC 7515 §4.1.11).
//
// Example:
//   reader at "[\"b64\",\"claim\"]", scratch = []
//   returns: out_crit with 2 elements, had_error = false
inline fn parse_crit_header_elements(
    reader:    json::Reader&,
    scratch:   u8[>..]&,
    out_crit:  CritParam[..8]&,
    had_error: bool&,
) {
    json::each_element(reader) {
        scratch.clear();
        let crit_name = json::read_string(reader, scratch);
        if is_standard_jws_header_param(crit_name) {
            had_error = true;
        }
        for &cp in out_crit {
            if cp.name[..] == crit_name {
                had_error = true; // RFC 7515 §4.1.11: senders MUST NOT use duplicate names
            }
        }
        if out_crit.len < out_crit.cap && crit_name.len <= 32 {
            var cp = CritParam { .. };
            cp.name.append(crit_name);
            out_crit.push(cp);
        } else {
            had_error = true;
        }
    };
    if out_crit.len == 0 {
        had_error = true;
    }
}

inline fn is_header_key_present(name: const u8[:], seen: const SeenHeaderKey[..8]) -> bool {
    for &o in seen {
        if o.name[..] == name { return true; }
    }
    return false;
}

// Parses a single member of a JWT header JSON object.
//
// Example:
//   key = "alg", reader at "\"HS256\"", scratch = []
//   returns: out_header.alg = JwtAlg.HS256, seen_alg = true
inline fn parse_jwt_header_member(
    key:         const u8[:],
    reader:      json::Reader&,
    scratch:     u8[>..]&,
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
        if seen_alg { had_error = true; }
        seen_alg = true;
        let alg_str = json::read_string(reader, scratch);
        out_header.alg = parse_jwt_alg(alg_str);
    } else if key == "typ" {
        if seen_typ { had_error = true; }
        seen_typ = true;
        let typ_str = json::read_string(reader, scratch);
        if typ_str.len <= out_header.typ.cap {
            out_header.typ.clear();
            out_header.typ.append(typ_str);
        } else { had_error = true; }
    } else if key == "kid" {
        if seen_kid { had_error = true; }
        seen_kid = true;
        let kid_str = json::read_string(reader, scratch);
        if kid_str.len <= out_header.kid.cap {
            out_header.kid.clear();
            out_header.kid.append(kid_str);
        } else { had_error = true; }
    } else if key == "cty" {
        if seen_cty { had_error = true; }
        seen_cty = true;
        let cty_str = json::read_string(reader, scratch);
        if cty_str.len <= out_header.cty.cap {
            out_header.cty.clear();
            out_header.cty.append(cty_str);
        } else { had_error = true; }
    } else if key == "crit" {
        if seen_crit { had_error = true; }
        seen_crit = true;
        let p = json::peek(reader);
        if p == '[' {
            parse_crit_header_elements(reader, scratch, out_header.crit, had_error);
        } else {
            json::skip(reader);
            had_error = true;
        }
    } else {
        if is_header_key_present(key, seen_others) { had_error = true; }
        if seen_others.len < seen_others.cap && key.len <= 64 {
            var item = SeenHeaderKey { .. };
            item.name.append(key);
            seen_others.push(item);
        } else {
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
    var reader = json::reader(json_bytes);
    var scratch: u8[>..] = [];
    out_header.kid.clear();
    out_header.cty.clear();
    out_header.typ.clear();
    out_header.crit.clear();
    var had_error = false;
    var seen_alg = false;
    var seen_typ = false;
    var seen_kid = false;
    var seen_cty = false;
    var seen_crit = false;
    var seen_others: SeenHeaderKey[..8] = [];

    json::each_member(reader) { key =>
        scratch.clear();
        parse_jwt_header_member(
            key, reader, scratch, out_header,
            seen_alg, seen_typ, seen_kid, seen_cty, seen_crit,
            seen_others, had_error,
        );
    };

    // RFC 7515 §4.1.11: Every parameter listed in crit MUST be present in the header
    for &cp in out_header.crit {
        if !is_header_key_present(cp.name[..], seen_others) {
            had_error = true;
        }
    }

    return json::finish(reader) && !had_error && seen_alg;
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
}

fn set_issuer(claims: JwtClaims&, iss: const u8[:]) -> bool {
    claims.iss.clear();
    guard iss.len <= claims.iss.cap else { return false; }
    claims.iss.append(iss);
    return true;
}

fn set_subject(claims: JwtClaims&, sub: const u8[:]) -> bool {
    claims.sub.clear();
    guard sub.len <= claims.sub.cap else { return false; }
    claims.sub.append(sub);
    return true;
}

fn set_audience(claims: JwtClaims&, aud: const u8[:]) -> bool {
    claims.aud.clear();
    claims.audiences.clear();
    guard aud.len <= claims.aud.cap && aud.len <= 128 else { return false; }
    claims.aud.append(aud);
    var item: u8[..128] = [];
    item.append(aud);
    claims.audiences.push(item);
    return true;
}

fn add_audience(claims: JwtClaims&, aud: const u8[:]) -> bool {
    guard claims.audiences.len < claims.audiences.cap && aud.len <= 128 else { return false; }
    if claims.aud.len == 0 {
        claims.aud.append(aud);
    }
    var item: u8[..128] = [];
    item.append(aud);
    claims.audiences.push(item);
    return true;
}

fn set_jwt_id(claims: JwtClaims&, jti: const u8[:]) -> bool {
    claims.jti.clear();
    guard jti.len <= claims.jti.cap else { return false; }
    claims.jti.append(jti);
    return true;
}

fn set_expiry(claims: JwtClaims&, exp_unix_sec: i64) {
    claims.exp = exp_unix_sec;
}

fn set_not_before(claims: JwtClaims&, nbf_unix_sec: i64) {
    claims.nbf = nbf_unix_sec;
}

fn set_issued_at(claims: JwtClaims&, iat_unix_sec: i64) {
    claims.iat = iat_unix_sec;
}

fn set_claim(claims: JwtClaims&, key: const u8[:], val: const u8[:]) -> bool {
    guard key.len <= 64 && val.len <= 256 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_str.append(val);
            c.val_num = 0;
            c.val_bool = false;
            c.is_num = false;
            c.is_bool = false;
            return true;
        }
    }
    guard claims.custom_claims.len < claims.custom_claims.cap else { return false; }
    var item = JwtClaimItem { .. };
    item.key.append(key);
    item.val_str.append(val);
    claims.custom_claims.push(item);
    return true;
}

fn set_claim_int(claims: JwtClaims&, key: const u8[:], val: i64) -> bool {
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
    guard claims.custom_claims.len < claims.custom_claims.cap else { return false; }
    var item = JwtClaimItem { .. };
    item.key.append(key);
    item.val_num = val;
    item.is_num = true;
    claims.custom_claims.push(item);
    return true;
}

fn set_claim_bool(claims: JwtClaims&, key: const u8[:], val: bool) -> bool {
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
    guard claims.custom_claims.len < claims.custom_claims.cap else { return false; }
    var item = JwtClaimItem { .. };
    item.key.append(key);
    item.val_bool = val;
    item.is_bool = true;
    claims.custom_claims.push(item);
    return true;
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

fn has_claim(claims: const JwtClaims&, key: const u8[:]) -> bool {
    if key == "iss" { return claims.iss.len > 0; }
    if key == "sub" { return claims.sub.len > 0; }
    if key == "aud" { return claims.aud.len > 0; }
    if key == "jti" { return claims.jti.len > 0; }
    if key == "exp" { return claims.exp >= 0; }
    if key == "nbf" { return claims.nbf >= 0; }
    if key == "iat" { return claims.iat >= 0; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            return true;
        }
    }
    return false;
}

// Serializes audiences array in JSON format (RFC 7519 §4.1.3).
inline fn serialize_audiences_array<B>(audiences: const u8[..128][..8], out: B&) {
    out.push('[');
    for i in audiences.len {
        if i > 0 { out.push(','); }
        json::format_string(out, audiences[i][..]);
    }
    out.push(']');
}

// Serializes a single custom JWT claim item in JSON format.
inline fn serialize_custom_claim<B>(c: const JwtClaimItem&, out: B&) {
    json::format_key(out, c.key[..]);
    if c.is_num {
        json::format_int(out, c.val_num);
    } else if c.is_bool {
        json::format_bool(out, c.val_bool);
    } else {
        json::format_string(out, c.val_str[..]);
    }
}

fn serialize_jwt_claims<B>(claims: const JwtClaims&, out: B&) {
    out.push('{');
    var first = true;

    if claims.iss.len > 0 {
        json::format_key(out, "iss");
        json::format_string(out, claims.iss[..]);
        first = false;
    }
    if claims.sub.len > 0 {
        if !first { out.push(','); }
        json::format_key(out, "sub");
        json::format_string(out, claims.sub[..]);
        first = false;
    }
    if claims.audiences.len > 1 {
        if !first { out.push(','); }
        json::format_key(out, "aud");
        serialize_audiences_array(claims.audiences, out);
        first = false;
    } else if claims.aud.len > 0 {
        if !first { out.push(','); }
        json::format_key(out, "aud");
        json::format_string(out, claims.aud[..]);
        first = false;
    }
    if claims.jti.len > 0 {
        if !first { out.push(','); }
        json::format_key(out, "jti");
        json::format_string(out, claims.jti[..]);
        first = false;
    }
    if claims.exp >= 0 {
        if !first { out.push(','); }
        json::format_key(out, "exp");
        json::format_int(out, claims.exp);
        first = false;
    }
    if claims.nbf >= 0 {
        if !first { out.push(','); }
        json::format_key(out, "nbf");
        json::format_int(out, claims.nbf);
        first = false;
    }
    if claims.iat >= 0 {
        if !first { out.push(','); }
        json::format_key(out, "iat");
        json::format_int(out, claims.iat);
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
    scratch:    u8[>..]&,
    out_claims: JwtClaims&,
) -> bool {
    guard json::peek(reader) == '"' else {
        json::skip(reader);
        return false;
    }
    scratch.clear();
    let s = json::read_string(reader, scratch);
    guard s.len <= 128 && out_claims.audiences.len < out_claims.audiences.cap else {
        return false;
    }
    if out_claims.aud.len == 0 {
        out_claims.aud.append(s);
    }
    var item: u8[..128] = [];
    item.append(s);
    out_claims.audiences.push(item);
    return true;
}

// Parses aud claim from a JSON string or array (RFC 7519 §4.1.3).
//
// Example:
//   reader at "\"https://api.example.com\"", scratch = []
//   returns: out_claims.aud = "https://api.example.com", had_error = false
inline fn parse_aud_claim(
    reader:     json::Reader&,
    scratch:    u8[>..]&,
    out_claims: JwtClaims&,
    had_error:  bool&,
) {
    let p = json::peek(reader);
    if p == '"' {
        let s = json::read_string(reader, scratch);
        guard s.len <= out_claims.aud.cap && out_claims.audiences.len < out_claims.audiences.cap && s.len <= 128 else {
            had_error = true;
            return;
        }
        out_claims.aud.clear();
        out_claims.aud.append(s);
        var item: u8[..128] = [];
        item.append(s);
        out_claims.audiences.push(item);
    } else if p == '[' {
        var count: i64 = 0;
        json::each_element(reader) {
            count += 1;
            if !try_append_audience_element(reader, scratch, out_claims) {
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
//   key = "role", reader at "\"admin\"", scratch = []
//   returns: out_claims.custom_claims includes ("role", "admin")
inline fn parse_custom_claim_entry(
    key:        const u8[:],
    reader:     json::Reader&,
    scratch:    u8[>..]&,
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
        let s = json::read_string(reader, scratch);
        if out_claims.custom_claims.len < out_claims.custom_claims.cap && key.len <= 64 && s.len <= 256 {
            var item = JwtClaimItem { .. };
            item.key.append(key);
            item.val_str.append(s);
            out_claims.custom_claims.push(item);
        } else {
            had_error = true;
        }
    } else if p == 't' || p == 'f' {
        let b = json::read_bool(reader);
        if out_claims.custom_claims.len < out_claims.custom_claims.cap && key.len <= 64 {
            var item = JwtClaimItem { .. };
            item.key.append(key);
            item.val_bool = b;
            item.is_bool = true;
            out_claims.custom_claims.push(item);
        } else {
            had_error = true;
        }
    } else if (p >= '0' && p <= '9') || p == '-' {
        let n = json::read_int(reader);
        if out_claims.custom_claims.len < out_claims.custom_claims.cap && key.len <= 64 {
            var item = JwtClaimItem { .. };
            item.key.append(key);
            item.val_num = n;
            item.is_num = true;
            out_claims.custom_claims.push(item);
        } else {
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
//   key = "sub", reader at "\"user_42\"", scratch = []
//   returns: true (handled), out_claims.sub = "user_42"
inline fn parse_jwt_standard_claim(
    key:        const u8[:],
    reader:     json::Reader&,
    scratch:    u8[>..]&,
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
        let s = json::read_string(reader, scratch);
        if s.len <= out_claims.iss.cap {
            out_claims.iss.clear();
            out_claims.iss.append(s);
        } else { had_error = true; }
        return true;
    }
    if key == "sub" {
        if seen_sub { had_error = true; }
        seen_sub = true;
        let s = json::read_string(reader, scratch);
        if s.len <= out_claims.sub.cap {
            out_claims.sub.clear();
            out_claims.sub.append(s);
        } else { had_error = true; }
        return true;
    }
    if key == "aud" {
        if seen_aud { had_error = true; }
        seen_aud = true;
        parse_aud_claim(reader, scratch, out_claims, had_error);
        return true;
    }
    if key == "jti" {
        if seen_jti { had_error = true; }
        seen_jti = true;
        let s = json::read_string(reader, scratch);
        if s.len <= out_claims.jti.cap {
            out_claims.jti.clear();
            out_claims.jti.append(s);
        } else { had_error = true; }
        return true;
    }
    if key == "exp" {
        if seen_exp { had_error = true; }
        seen_exp = true;
        let p = json::peek(reader);
        if (p >= '0' && p <= '9') || p == '-' {
            let val = json::read_number(reader) as i64;
            if val < 0 { had_error = true; } else { out_claims.exp = val; }
        } else { json::skip(reader); had_error = true; }
        return true;
    }
    if key == "nbf" {
        if seen_nbf { had_error = true; }
        seen_nbf = true;
        let p = json::peek(reader);
        if (p >= '0' && p <= '9') || p == '-' {
            let val = json::read_number(reader) as i64;
            if val < 0 { had_error = true; } else { out_claims.nbf = val; }
        } else { json::skip(reader); had_error = true; }
        return true;
    }
    if key == "iat" {
        if seen_iat { had_error = true; }
        seen_iat = true;
        let p = json::peek(reader);
        if (p >= '0' && p <= '9') || p == '-' {
            let val = json::read_number(reader) as i64;
            if val < 0 { had_error = true; } else { out_claims.iat = val; }
        } else { json::skip(reader); had_error = true; }
        return true;
    }
    return false;
}

// Parses a decoded JSON byte slice into a JwtClaims struct (RFC 7519 §4).
//
// Example:
//   json_bytes = "{\"sub\":\"user123\",\"exp\":1700000000}"
//   returns: ok = true, out_claims.sub = "user123"
fn parse_jwt_claims_json(json_bytes: const u8[:], out_claims: JwtClaims&) -> bool {
    var reader = json::reader(json_bytes);
    var scratch: u8[>..] = [];
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
        scratch.clear();
        let handled = parse_jwt_standard_claim(
            key, reader, scratch, out_claims,
            seen_iss, seen_sub, seen_aud, seen_jti, seen_exp, seen_nbf, seen_iat,
            had_error,
        );
        if !handled {
            if seen_custom_keys_contains(key, seen_custom) {
                had_error = true;
            }
            if seen_custom.len < seen_custom.cap && key.len <= 128 {
                var item = SeenCustomKey { .. };
                item.name.append(key);
                seen_custom.push(item);
            } else {
                had_error = true;
            }
            parse_custom_claim_entry(key, reader, scratch, out_claims, had_error);
        }
    };
    return json::finish(reader) && !had_error;
}

// ---- JWT Validation Options ----------------------------------------------

struct JwtValidationOptions {
    expected_alg:      JwtAlg         = JwtAlg.HS256,
    expected_issuer:   u8[..128]      = [],
    expected_audience: u8[..128]      = [],
    expected_subject:  u8[..128]      = [],
    expected_typ:      u8[..32]       = [], // RFC 8725 §3.11 & RFC 9068: Explicit type verification
    supported_crit:    CritParam[..8] = [], // RFC 7515 §4.1.11 / RFC 8725 §3.8: Supported critical parameters
    leeway_seconds:    i64            = DEFAULT_JWT_LEEWAY_SECONDS,
    require_exp:       bool           = true,
    require_nbf:       bool           = false,
    allow_none_alg:    bool           = false, // RFC 8725 §3.1: Strictly false by default
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

fn set_expected_type(opts: JwtValidationOptions&, typ: const u8[:]) -> bool {
    opts.expected_typ.clear();
    guard typ.len <= opts.expected_typ.cap else { return false; }
    opts.expected_typ.append(typ);
    return true;
}

fn add_supported_crit(opts: JwtValidationOptions&, name: const u8[:]) -> bool {
    guard opts.supported_crit.len < opts.supported_crit.cap && name.len <= 32 else { return false; }
    var item = CritParam { .. };
    item.name.append(name);
    opts.supported_crit.push(item);
    return true;
}

// ---- JWS Signing Pipeline (HMAC & Ed25519) -------------------------------

// Serializes Header and Claims into Base64URL-encoded signing input: `<hdr_b64>.<clm_b64>`
fn build_jwt_signing_input<B>(
    header:    const JwtHeader&,
    claims:    const JwtClaims&,
    out_token: B&,
) {
    var hdr_json: u8[>..] = [];
    serialize_jwt_header(header, hdr_json);
    core::base64url_encode(hdr_json[..], out_token);
    out_token.push('.');

    var clm_json: u8[>..] = [];
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

    build_jwt_signing_input(header, claims, out_token);
    let signing_input = out_token[..];
    append_jwt_eddsa_signature(seed_key, signing_input, out_token);
    return true;
}

// ---- JWT Verification & Claim Validation ---------------------------------

// Hard bounds on raw token and component sizes to prevent parser DoS and memory exhaustion
const MAX_JWT_TOKEN_LEN:       i64 = 8192;
const MAX_JWT_HEADER_PART_LEN: i64 = 2048;
const MAX_JWT_CLAIMS_PART_LEN: i64 = 4096;

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
    guard dot2 > (dot1 + 1) && (dot2 - dot1) <= MAX_JWT_CLAIMS_PART_LEN else { return false; }
    return true;
}

fn validate_jwt_expiration(exp: i64, require_exp: bool, leeway: i64, now_unix_sec: i64) -> bool {
    guard leeway >= 0 else { return false; }
    guard now_unix_sec >= 0 else { return false; }
    if exp >= 0 {
        let max_exp_cutoff = if exp > 9223372036854775807 - leeway {
            9223372036854775807
        } else {
            exp + leeway
        };
        return now_unix_sec <= max_exp_cutoff;
    }
    return !require_exp;
}

fn validate_jwt_not_before(nbf: i64, require_nbf: bool, leeway: i64, now_unix_sec: i64) -> bool {
    guard leeway >= 0 else { return false; }
    guard now_unix_sec >= 0 else { return false; }
    if nbf >= 0 {
        let min_nbf_cutoff = if nbf < leeway {
            0
        } else {
            nbf - leeway
        };
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

fn validate_jwt_identity_claims(claims: const JwtClaims&, options: const JwtValidationOptions&) -> JwtError {
    if options.expected_issuer.len > 0 && claims.iss[..] != options.expected_issuer[..] {
        return JwtError.IssuerMismatch;
    }
    if options.expected_audience.len > 0 && !claims_match_audience(claims, options.expected_audience[..]) {
        return JwtError.AudienceMismatch;
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
    guard core::base64url_decode(hdr_b64, hdr_json) else {
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
    guard core::base64url_decode(clm_b64, clm_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_claims_json(clm_json[..], out_claims) else {
        return JwtError.InvalidClaimsJson;
    }
    return JwtError.None;
}

// Decodes and parses header only without signature verification (RFC 7519).
fn parse_jwt_header_only(
    token:      const u8[:],
    out_header: JwtHeader&,
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
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
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }

    let hdr_err = decode_jwt_header(token[..dot1], out_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let clm_start = core::add_sat_i64(dot1, 1);
    return decode_jwt_claims(token[clm_start..dot2], out_claims);
}

fn verify_jwt_algorithm(header_alg: JwtAlg, expected_alg: JwtAlg, allow_none: bool) -> JwtError {
    if header_alg == JwtAlg.Unknown {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.None && !allow_none {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg != expected_alg {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}

fn is_matching_jwt_typ(header_typ: const u8[:], expected_typ: const u8[:]) -> bool {
    if core::eq_ascii_fold(header_typ, expected_typ) {
        return true;
    }
    // Handle "application/" media type prefix equivalence per RFC 8725 §3.11
    if core::starts_with(expected_typ, "application/") {
        if core::eq_ascii_fold(header_typ, expected_typ[12..]) {
            return true;
        }
    }
    if core::starts_with(header_typ, "application/") {
        if core::eq_ascii_fold(header_typ[12..], expected_typ) {
            return true;
        }
    }
    return false;
}

inline fn is_crit_param_supported(cp_name: const u8[:], supported: const CritParam[..8]) -> bool {
    for &sc in supported {
        if sc.name[..] == cp_name { return true; }
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

    let hdr_err = decode_jwt_header(token[..dot1], out_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let hdr_rule_err = verify_jwt_header_rules(out_header, options);
    guard hdr_rule_err == JwtError.None else { return hdr_rule_err; }

    var sig_bytes: u8[..128] = [];
    let sig_start = core::add_sat_i64(dot2, 1);
    guard core::base64url_decode(token[sig_start..], sig_bytes) else {
        return JwtError.InvalidBase64;
    }

    let signing_input = token[..dot2];
    guard verify_jwt_hmac_signature(out_header.alg, secret_key, signing_input, sig_bytes[..]) else {
        return JwtError.SignatureInvalid;
    }

    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], out_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    return validate_jwt_claims_rules(out_claims, options, now_unix_sec);
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

    let hdr_err = decode_jwt_header(token[..dot1], out_header);
    guard hdr_err == JwtError.None else { return hdr_err; }

    let hdr_rule_err = verify_jwt_header_rules(out_header, options);
    guard hdr_rule_err == JwtError.None else { return hdr_rule_err; }

    if out_header.alg != JwtAlg.EdDSA {
        return JwtError.AlgorithmMismatch;
    }

    var sig_bytes: u8[..128] = [];
    let sig_start = core::add_sat_i64(dot2, 1);
    guard core::base64url_decode(token[sig_start..], sig_bytes) else {
        return JwtError.InvalidBase64;
    }

    let signing_input = token[..dot2];
    guard verify_jwt_eddsa_signature(public_key, signing_input, sig_bytes[..]) else {
        return JwtError.SignatureInvalid;
    }

    let clm_start = core::add_sat_i64(dot1, 1);
    let clm_err = decode_jwt_claims(token[clm_start..dot2], out_claims);
    guard clm_err == JwtError.None else { return clm_err; }

    return validate_jwt_claims_rules(out_claims, options, now_unix_sec);
}
