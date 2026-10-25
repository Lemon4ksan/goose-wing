// Universal Zero-Allocation JSON Web Token (JWT / RFC 7519) and JSON Web Signature (JWS / RFC 7515) Engine.
// Supports symmetric HMAC (HS256, HS384, HS512) and asymmetric Ed25519 (EdDSA / RFC 8037).
// Enforces RFC 8725 BCP Security Defenses (algorithm pinning, none-alg rejection, clock leeway, replay guards).
namespace wing;

import std;
import json;
import core from "..";

// ---- 1. JWT / JWS Algorithm & Error Models ----------------------------------

enum JwtAlg {
    None,    // Disallowed by default (RFC 8725 Section 3.1 / CVE-2015-9235 defense)
    HS256,   // HMAC using SHA-256 (RFC 7518 Section 3.2)
    HS384,   // HMAC using SHA-384
    HS512,   // HMAC using SHA-512
    EdDSA,   // Ed25519 digital signature (RFC 8037 Section 3.1)
}

fn jwt_alg_to_string(alg: JwtAlg) -> const u8[:] {
    return match alg {
        None => "none",
        HS256 => "HS256",
        HS384 => "HS384",
        HS512 => "HS512",
        EdDSA => "EdDSA",
    };
}

fn parse_jwt_alg(s: const u8[:]) -> JwtAlg {
    if s == "HS256" { return JwtAlg.HS256; }
    if s == "HS384" { return JwtAlg.HS384; }
    if s == "HS512" { return JwtAlg.HS512; }
    if s == "EdDSA" { return JwtAlg.EdDSA; }
    if s == "none" { return JwtAlg.None; }
    return JwtAlg.None;
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
    };
}

// ---- 2. JWT Header Model & Parser -------------------------------------------

struct JwtHeader {
    alg: JwtAlg = JwtAlg.HS256,
    typ: u8[..32] = "JWT",
    kid: u8[..64] = [],
    cty: u8[..32] = [],
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
    out.push('}');
}

fn parse_jwt_header_json(json_bytes: const u8[:], out_header: JwtHeader&) -> bool {
    var reader = json::reader(json_bytes);
    var scratch: u8[>..] = [];
    out_header.kid.clear();
    out_header.cty.clear();
    out_header.typ.clear();
    out_header.typ.append("JWT");

    json::each_member(reader) { key =>
        scratch.clear();
        if key == "alg" {
            let alg_str = json::read_string(reader, scratch);
            out_header.alg = parse_jwt_alg(alg_str);
        } else if key == "typ" {
            let typ_str = json::read_string(reader, scratch);
            out_header.typ.clear();
            out_header.typ.append(typ_str);
        } else if key == "kid" {
            let kid_str = json::read_string(reader, scratch);
            out_header.kid.clear();
            out_header.kid.append(kid_str);
        } else if key == "cty" {
            let cty_str = json::read_string(reader, scratch);
            out_header.cty.clear();
            out_header.cty.append(cty_str);
        } else {
            json::skip(reader);
        }
    };
    return json::finish(reader);
}

// ---- 3. JWT Claims Model & Parser -------------------------------------------

struct JwtClaimItem {
    key: u8[..64] = [],
    val_str: u8[..256] = [],
    val_num: i64 = 0,
    val_bool: bool = false,
    is_num: bool = false,
    is_bool: bool = false,
}

struct JwtClaims {
    iss: u8[..128] = [],
    sub: u8[..128] = [],
    aud: u8[..128] = [],
    jti: u8[..64] = [],
    exp: i64 = -1,
    nbf: i64 = -1,
    iat: i64 = -1,
    custom_claims: JwtClaimItem[..16] = [],
}

fn new_jwt_claims() -> JwtClaims {
    return JwtClaims { .. };
}

fn set_issuer(claims: JwtClaims&, iss: const u8[:]) {
    claims.iss.clear();
    claims.iss.append(iss);
}

fn set_subject(claims: JwtClaims&, sub: const u8[:]) {
    claims.sub.clear();
    claims.sub.append(sub);
}

fn set_audience(claims: JwtClaims&, aud: const u8[:]) {
    claims.aud.clear();
    claims.aud.append(aud);
}

fn set_jwt_id(claims: JwtClaims&, jti: const u8[:]) {
    claims.jti.clear();
    claims.jti.append(jti);
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

fn set_claim(claims: JwtClaims&, key: const u8[:], val: const u8[:]) {
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_str.append(val);
            c.is_num = false;
            c.is_bool = false;
            return;
        }
    }
    if claims.custom_claims.len < claims.custom_claims.cap {
        var item = JwtClaimItem { .. };
        item.key.append(key);
        item.val_str.append(val);
        claims.custom_claims.push(item);
    }
}

fn set_claim_int(claims: JwtClaims&, key: const u8[:], val: i64) {
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_num = val;
            c.is_num = true;
            c.is_bool = false;
            return;
        }
    }
    if claims.custom_claims.len < claims.custom_claims.cap {
        var item = JwtClaimItem { .. };
        item.key.append(key);
        item.val_num = val;
        item.is_num = true;
        claims.custom_claims.push(item);
    }
}

fn set_claim_bool(claims: JwtClaims&, key: const u8[:], val: bool) {
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_bool = val;
            c.is_bool = true;
            c.is_num = false;
            return;
        }
    }
    if claims.custom_claims.len < claims.custom_claims.cap {
        var item = JwtClaimItem { .. };
        item.key.append(key);
        item.val_bool = val;
        item.is_bool = true;
        claims.custom_claims.push(item);
    }
}

fn claim_str(claims: const JwtClaims&, key: const u8[:]) -> const u8[:] {
    if key == "iss" { return claims.iss[..]; }
    if key == "sub" { return claims.sub[..]; }
    if key == "aud" { return claims.aud[..]; }
    if key == "jti" { return claims.jti[..]; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
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
    if claims.aud.len > 0 {
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
        json::format_key(out, c.key[..]);
        if c.is_num {
            json::format_int(out, c.val_num);
        } else if c.is_bool {
            json::format_bool(out, c.val_bool);
        } else {
            json::format_string(out, c.val_str[..]);
        }
        first = false;
    }

    out.push('}');
}

fn parse_jwt_claims_json(json_bytes: const u8[:], out_claims: JwtClaims&) -> bool {
    var reader = json::reader(json_bytes);
    var scratch: u8[>..] = [];
    out_claims.iss.clear();
    out_claims.sub.clear();
    out_claims.aud.clear();
    out_claims.jti.clear();
    out_claims.exp = -1;
    out_claims.nbf = -1;
    out_claims.iat = -1;
    out_claims.custom_claims.clear();

    json::each_member(reader) { key =>
        scratch.clear();
        if key == "iss" {
            let s = json::read_string(reader, scratch);
            out_claims.iss.append(s);
        } else if key == "sub" {
            let s = json::read_string(reader, scratch);
            out_claims.sub.append(s);
        } else if key == "aud" {
            let p = json::peek(reader);
            if p == '"' {
                let s = json::read_string(reader, scratch);
                out_claims.aud.append(s);
            } else {
                json::skip(reader);
            }
        } else if key == "jti" {
            let s = json::read_string(reader, scratch);
            out_claims.jti.append(s);
        } else if key == "exp" {
            out_claims.exp = json::read_int(reader);
        } else if key == "nbf" {
            out_claims.nbf = json::read_int(reader);
        } else if key == "iat" {
            out_claims.iat = json::read_int(reader);
        } else {
            let p = json::peek(reader);
            if p == '"' {
                let s = json::read_string(reader, scratch);
                if out_claims.custom_claims.len < out_claims.custom_claims.cap {
                    var item = JwtClaimItem { .. };
                    item.key.append(key);
                    item.val_str.append(s);
                    out_claims.custom_claims.push(item);
                }
            } else if p == 't' || p == 'f' {
                let b = json::read_bool(reader);
                if out_claims.custom_claims.len < out_claims.custom_claims.cap {
                    var item = JwtClaimItem { .. };
                    item.key.append(key);
                    item.val_bool = b;
                    item.is_bool = true;
                    out_claims.custom_claims.push(item);
                }
            } else if (p >= '0' && p <= '9') || p == '-' {
                let n = json::read_int(reader);
                if out_claims.custom_claims.len < out_claims.custom_claims.cap {
                    var item = JwtClaimItem { .. };
                    item.key.append(key);
                    item.val_num = n;
                    item.is_num = true;
                    out_claims.custom_claims.push(item);
                }
            } else {
                json::skip(reader);
            }
        }
    };
    return json::finish(reader);
}

// ---- 4. JWT Validation Options ----------------------------------------------

struct JwtValidationOptions {
    expected_alg: JwtAlg = JwtAlg.HS256,
    expected_issuer: u8[..128] = [],
    expected_audience: u8[..128] = [],
    expected_subject: u8[..128] = [],
    leeway_seconds: i64 = 60,
    require_exp: bool = true,
    require_nbf: bool = false,
    allow_none_alg: bool = false, // RFC 8725 §3.1: Strictly false by default
}

fn default_jwt_validation_options(expected_alg: JwtAlg = JwtAlg.HS256) -> JwtValidationOptions {
    return JwtValidationOptions {
        expected_alg: expected_alg,
        leeway_seconds: 60,
        require_exp: true,
        require_nbf: false,
        allow_none_alg: false,
        ..
    };
}

// ---- 5. JWS Signing Pipeline (HMAC & Ed25519) -------------------------------

// Signs a JWT using symmetric HMAC (HS256, HS384, HS512 per RFC 7518)
fn sign_jwt_hmac<B>(
    header: const JwtHeader&,
    claims: const JwtClaims&,
    secret_key: const u8[:],
    out_token: B&
) -> bool {
    guard header.alg == JwtAlg.HS256 || header.alg == JwtAlg.HS384 || header.alg == JwtAlg.HS512 else {
        return false;
    }
    guard secret_key.len > 0 else { return false; }
    out_token.clear();

    // 1. Serialize Header -> Base64URL
    var hdr_json: u8[>..] = [];
    serialize_jwt_header(header, hdr_json);
    core::base64url_encode(hdr_json[..], out_token);
    out_token.push('.');

    // 2. Serialize Claims -> Base64URL
    var clm_json: u8[>..] = [];
    serialize_jwt_claims(claims, clm_json);
    var clm_b64: u8[>..] = [];
    core::base64url_encode(clm_json[..], clm_b64);
    out_token.append(clm_b64[..]);

    // 3. Compute MAC over signing input `<hdr_b64>.<clm_b64>`
    let signing_input = out_token[..];
    out_token.push('.');

    if header.alg == JwtAlg.HS256 {
        let mac256 = core::hmac_sha256(secret_key, signing_input);
        core::base64url_encode(mac256[..], out_token);
    } else if header.alg == JwtAlg.HS384 {
        let mac384 = core::hmac_sha384(secret_key, signing_input);
        core::base64url_encode(mac384[..], out_token);
    } else if header.alg == JwtAlg.HS512 {
        let mac512 = core::hmac_sha512(secret_key, signing_input);
        core::base64url_encode(mac512[..], out_token);
    }

    return true;
}

// Signs a JWT using asymmetric Ed25519 (EdDSA per RFC 8037)
fn sign_jwt_eddsa<B>(
    header: const JwtHeader&,
    claims: const JwtClaims&,
    seed_key: const u8[32],
    out_token: B&
) -> bool {
    guard header.alg == JwtAlg.EdDSA else { return false; }
    out_token.clear();

    // 1. Serialize Header -> Base64URL
    var hdr_json: u8[>..] = [];
    serialize_jwt_header(header, hdr_json);
    core::base64url_encode(hdr_json[..], out_token);
    out_token.push('.');

    // 2. Serialize Claims -> Base64URL
    var clm_json: u8[>..] = [];
    serialize_jwt_claims(claims, clm_json);
    var clm_b64: u8[>..] = [];
    core::base64url_encode(clm_json[..], clm_b64);
    out_token.append(clm_b64[..]);

    // 3. Sign `<hdr_b64>.<clm_b64>` using Ed25519
    let signing_input = out_token[..];
    let sig64 = core::ed25519_sign(seed_key, signing_input);

    // 4. Append signature Base64URL
    out_token.push('.');
    core::base64url_encode(sig64[..], out_token);

    return true;
}

// ---- 6. JWT Verification & Claim Validation ---------------------------------

fn split_jwt_parts(
    token: const u8[:],
    dot1: i64&,
    dot2: i64&
) -> bool {
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
    return dot1 > 0 && dot2 > (dot1 + 1);
}

// Validates time and identity claims against options
fn validate_jwt_claims_rules(
    claims: const JwtClaims&,
    options: const JwtValidationOptions&,
    now_unix_sec: i64
) -> JwtError {
    // 1. Expiration check (exp)
    if claims.exp >= 0 {
        if now_unix_sec > (claims.exp + options.leeway_seconds) {
            return JwtError.TokenExpired;
        }
    } else if options.require_exp {
        return JwtError.TokenExpired;
    }

    // 2. Not before check (nbf)
    if claims.nbf >= 0 {
        if now_unix_sec < (claims.nbf - options.leeway_seconds) {
            return JwtError.TokenNotYetValid;
        }
    } else if options.require_nbf {
        return JwtError.TokenNotYetValid;
    }

    // 3. Issuer check (iss)
    if options.expected_issuer.len > 0 {
        if claims.iss[..] != options.expected_issuer[..] {
            return JwtError.IssuerMismatch;
        }
    }

    // 4. Audience check (aud)
    if options.expected_audience.len > 0 {
        if claims.aud[..] != options.expected_audience[..] {
            return JwtError.AudienceMismatch;
        }
    }

    // 5. Subject check (sub)
    if options.expected_subject.len > 0 {
        if claims.sub[..] != options.expected_subject[..] {
            return JwtError.SubjectMismatch;
        }
    }

    return JwtError.None;
}

// Decodes and parses header and claims without signature verification (useful for inspection)
fn parse_jwt_unverified(
    token: const u8[:],
    out_header: JwtHeader&,
    out_claims: JwtClaims&
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }

    let hdr_b64 = token[..dot1];
    let clm_b64 = token[(dot1 + 1)..dot2];

    var hdr_json: u8[>..] = [];
    guard core::base64url_decode(hdr_b64, hdr_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_header_json(hdr_json[..], out_header) else {
        return JwtError.InvalidHeaderJson;
    }

    var clm_json: u8[>..] = [];
    guard core::base64url_decode(clm_b64, clm_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_claims_json(clm_json[..], out_claims) else {
        return JwtError.InvalidClaimsJson;
    }

    return JwtError.None;
}

// Verifies a JWT signed with HMAC (HS256, HS384, HS512)
fn verify_jwt_hmac(
    token: const u8[:],
    secret_key: const u8[:],
    options: const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header: JwtHeader&,
    out_claims: JwtClaims&
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }

    let hdr_b64 = token[..dot1];
    let clm_b64 = token[(dot1 + 1)..dot2];
    let sig_b64 = token[(dot2 + 1)..];

    // Decode Header
    var hdr_json: u8[>..] = [];
    guard core::base64url_decode(hdr_b64, hdr_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_header_json(hdr_json[..], out_header) else {
        return JwtError.InvalidHeaderJson;
    }

    // RFC 8725 Section 3.1: Strict algorithm verification (prevents alg confusion)
    if out_header.alg == JwtAlg.None && !options.allow_none_alg {
        return JwtError.UnsupportedAlgorithm;
    }
    if out_header.alg != options.expected_alg {
        return JwtError.AlgorithmMismatch;
    }

    // Decode Signature bytes
    var sig_bytes: u8[>..] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else {
        return JwtError.InvalidBase64;
    }

    // Verify MAC with constant-time comparison
    let signing_input = token[..dot2];
    if out_header.alg == JwtAlg.HS256 {
        guard sig_bytes.len == 32 else { return JwtError.SignatureInvalid; }
        let expected = core::hmac_sha256(secret_key, signing_input);
        guard core::ct_eq_bytes(expected[..], sig_bytes[..]) else {
            return JwtError.SignatureInvalid;
        }
    } else if out_header.alg == JwtAlg.HS384 {
        guard sig_bytes.len == 48 else { return JwtError.SignatureInvalid; }
        let expected = core::hmac_sha384(secret_key, signing_input);
        guard core::ct_eq_bytes(expected[..], sig_bytes[..]) else {
            return JwtError.SignatureInvalid;
        }
    } else if out_header.alg == JwtAlg.HS512 {
        guard sig_bytes.len == 64 else { return JwtError.SignatureInvalid; }
        let expected = core::hmac_sha512(secret_key, signing_input);
        guard core::ct_eq_bytes(expected[..], sig_bytes[..]) else {
            return JwtError.SignatureInvalid;
        }
    } else {
        return JwtError.UnsupportedAlgorithm;
    }

    // Decode Claims
    var clm_json: u8[>..] = [];
    guard core::base64url_decode(clm_b64, clm_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_claims_json(clm_json[..], out_claims) else {
        return JwtError.InvalidClaimsJson;
    }

    // Validate claims rules (exp, nbf, iss, aud, sub)
    return validate_jwt_claims_rules(out_claims, options, now_unix_sec);
}

// Verifies a JWT signed with Ed25519 (EdDSA)
fn verify_jwt_eddsa(
    token: const u8[:],
    public_key: const u8[32],
    options: const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header: JwtHeader&,
    out_claims: JwtClaims&
) -> JwtError {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(token, dot1, dot2) else {
        return JwtError.MalformedToken;
    }

    let hdr_b64 = token[..dot1];
    let clm_b64 = token[(dot1 + 1)..dot2];
    let sig_b64 = token[(dot2 + 1)..];

    // Decode Header
    var hdr_json: u8[>..] = [];
    guard core::base64url_decode(hdr_b64, hdr_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_header_json(hdr_json[..], out_header) else {
        return JwtError.InvalidHeaderJson;
    }

    // Check algorithm
    if out_header.alg != JwtAlg.EdDSA {
        return JwtError.AlgorithmMismatch;
    }

    // Decode Signature (Ed25519 signature is strictly 64 bytes)
    var sig_bytes: u8[>..] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else {
        return JwtError.InvalidBase64;
    }
    guard sig_bytes.len == 64 else { return JwtError.SignatureInvalid; }

    var sig64: u8[64] = [0; 64];
    for i in 64 {
        sig64[i] = sig_bytes[i];
    }

    // Verify Ed25519 signature
    let signing_input = token[..dot2];
    guard core::ed25519_verify(public_key, signing_input, sig64) else {
        return JwtError.SignatureInvalid;
    }

    // Decode Claims
    var clm_json: u8[>..] = [];
    guard core::base64url_decode(clm_b64, clm_json) else {
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_claims_json(clm_json[..], out_claims) else {
        return JwtError.InvalidClaimsJson;
    }

    // Validate claims rules
    return validate_jwt_claims_rules(out_claims, options, now_unix_sec);
}
