// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Universal Zero-Allocation JSON Web Key (JWK) and JSON Web Key Set (JWKS / RFC 7517) Engine.
// Supports symmetric ("oct" / HMAC) and asymmetric Edwards curves ("OKP" / Ed25519 per RFC 8037).
// Provides serialization, parsing, key rotation indexing, and integrated JWT verification.
namespace wing;

import std;
import json;
import core from "..";
import .jwt;

// ---- 1. JWK / JWKS Key Models -----------------------------------------------

enum JwkKeyType {
    OKP,    // Octet Key Pair (RFC 8037: Ed25519)
    Oct,    // Symmetric Octet Sequence (RFC 7518: HMAC)
}

fn jwk_key_type_to_string(kty: JwkKeyType) -> const u8[:] {
    return match kty {
        OKP => "OKP",
        Oct => "oct",
    };
}

fn parse_jwk_key_type(s: const u8[:]) -> JwkKeyType {
    if s == "OKP" { return JwkKeyType.OKP; }
    if s == "oct" { return JwkKeyType.Oct; }
    return JwkKeyType.OKP;
}

struct JwksKey {
    kty: JwkKeyType = JwkKeyType.OKP,
    crv: u8[..32] = "",
    alg: JwtAlg = JwtAlg.None,
    use: u8[..16] = "sig",
    kid: u8[..64] = [],
    symmetric_key: u8[..64] = [],
    public_key: u8[32] = [0; 32],
    valid: bool = false,
}

struct Jwks {
    keys: JwksKey[..16] = [],
}

fn new_jwks() -> Jwks {
    return Jwks { .. };
}

// Registers an asymmetric Ed25519 public key in the key set
fn add_ed25519_key(
    jwks: Jwks&,
    kid: const u8[:],
    pub_key: const u8[32],
) -> bool {
    guard jwks.keys.len < jwks.keys.cap else { return false; }
    guard kid.len <= 64 else { return false; }
    var key = JwksKey {
        kty: JwkKeyType.OKP,
        crv: "Ed25519",
        alg: JwtAlg.EdDSA,
        use: "sig",
        public_key: pub_key,
        valid: true,
        ..
    };
    key.kid.append(kid);
    jwks.keys.push(key);
    return true;
}

// Registers a symmetric HMAC secret key in the key set
fn add_symmetric_key(
    jwks: Jwks&,
    kid: const u8[:],
    alg: JwtAlg,
    secret_key: const u8[:],
) -> bool {
    guard jwks.keys.len < jwks.keys.cap else { return false; }
    guard kid.len <= 64 else { return false; }
    guard secret_key.len > 0 && secret_key.len <= 64 else { return false; }
    var key = JwksKey {
        kty: JwkKeyType.Oct,
        crv: "",
        alg: alg,
        use: "sig",
        valid: true,
        ..
    };
    key.kid.append(kid);
    key.symmetric_key.append(secret_key);
    jwks.keys.push(key);
    return true;
}

// Finds the index of a key by kid (-1 if not found)
fn find_key(jwks: const Jwks&, kid: const u8[:]) -> i32 {
    for i in jwks.keys.len {
        let k = jwks.keys[i];
        if k.valid && k.kid[..] == kid {
            return i as i32;
        }
    }
    return -1;
}

// ---- 2. JWK Canonicalization & Thumbprint (RFC 7638 / RFC 8037) -------------

// Computes RFC 7638 / RFC 8037 Canonical JSON representation of a JWK:
// - Lexicographically sorted required members only
// - No whitespace
// - OKP (RFC 8037 §4): "crv", "kty", "x"
// - oct (RFC 7638 §3.2): "k", "kty"
// - Ignores optional members (alg, use, kid)
fn compute_canonical_jwk<B>(key: const JwksKey&, out: B&) -> bool {
    out.clear();
    if key.kty == JwkKeyType.OKP {
        guard key.crv.len > 0 else { return false; }
        out.append("{\"crv\":\"");
        out.append(key.crv[..]);
        out.append("\",\"kty\":\"OKP\",\"x\":\"");
        var x_b64: u8[..64] = [];
        core::base64url_encode(key.public_key[..], x_b64);
        out.append(x_b64[..]);
        out.append("\"}");
        return true;
    } else if key.kty == JwkKeyType.Oct {
        guard key.symmetric_key.len > 0 else { return false; }
        out.append("{\"k\":\"");
        var k_b64: u8[..128] = [];
        core::base64url_encode(key.symmetric_key[..], k_b64);
        out.append(k_b64[..]);
        out.append("\",\"kty\":\"oct\"}");
        return true;
    }
    return false;
}

// Computes the RFC 7638 JWK Thumbprint:
// SHA-256 hash of canonical JSON, base64url-encoded without padding.
fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool {
    out.clear();
    var canonical: u8[..256] = [];
    guard compute_canonical_jwk(key, canonical) else { return false; }
    let digest = core::sha256(canonical[..]);
    core::base64url_encode(digest[..], out);
    return true;
}

// ---- 3. JWKS Serialization & Parsing (RFC 7517) ------------------------------

fn serialize_jwk_key<B>(k: const JwksKey&, out: B&) {
    out.append("{\"kty\":");
    json::format_string(out, jwk_key_type_to_string(k.kty));

    if k.kty == JwkKeyType.OKP {
        out.append(",\"crv\":");
        json::format_string(out, k.crv[..]);
        out.append(",\"x\":");
        var x_b64: u8[..64] = [];
        core::base64url_encode(k.public_key[..], x_b64);
        json::format_string(out, x_b64[..]);
    } else {
        out.append(",\"k\":");
        var k_b64: u8[..128] = [];
        core::base64url_encode(k.symmetric_key[..], k_b64);
        json::format_string(out, k_b64[..]);
    }

    if k.alg != JwtAlg.None {
        out.append(",\"alg\":");
        json::format_string(out, jwt_alg_to_string(k.alg));
    }
    if k.use.len > 0 {
        out.append(",\"use\":");
        json::format_string(out, k.use[..]);
    }
    if k.kid.len > 0 {
        out.append(",\"kid\":");
        json::format_string(out, k.kid[..]);
    }
    out.push('}');
}

// Serializes a JWKS struct into RFC 7517 JSON format: `{"keys": [ {...}, ... ]}`
fn serialize_jwks<B>(jwks: const Jwks&, out: B&) {
    out.append("{\"keys\":[");
    var first = true;
    for &k in jwks.keys {
        if !k.valid { continue; }
        if !first { out.push(','); }
        first = false;
        serialize_jwk_key(k, out);
    }
    out.append("]}");
}

fn parse_jwk_key_core_type(
    field_key: const u8[:],
    reader: json::Reader&,
    scratch: u8[>..]&,
    key_item: JwksKey&,
) -> bool {
    if field_key == "kty" {
        let kty_str = json::read_string(reader, scratch);
        key_item.kty = parse_jwk_key_type(kty_str);
        return true;
    }
    if field_key == "crv" {
        let crv_str = json::read_string(reader, scratch);
        if crv_str.len <= key_item.crv.cap {
            key_item.crv.clear();
            key_item.crv.append(crv_str);
        }
        return true;
    }
    if field_key == "alg" {
        let alg_str = json::read_string(reader, scratch);
        key_item.alg = parse_jwt_alg(alg_str);
        return true;
    }
    return false;
}

fn parse_jwk_key_ident(
    field_key: const u8[:],
    reader: json::Reader&,
    scratch: u8[>..]&,
    key_item: JwksKey&,
) -> bool {
    if field_key == "use" {
        let use_str = json::read_string(reader, scratch);
        if use_str.len <= key_item.use.cap {
            key_item.use.clear();
            key_item.use.append(use_str);
        }
        return true;
    }
    if field_key == "kid" {
        let kid_str = json::read_string(reader, scratch);
        if kid_str.len <= key_item.kid.cap {
            key_item.kid.clear();
            key_item.kid.append(kid_str);
        }
        return true;
    }
    return false;
}

fn parse_jwk_key_material(
    field_key: const u8[:],
    reader: json::Reader&,
    scratch: u8[>..]&,
    raw_x: u8[..128]&,
    raw_k: u8[..128]&,
) -> bool {
    if field_key == "x" {
        let x_str = json::read_string(reader, scratch);
        if x_str.len <= raw_x.cap {
            raw_x.clear();
            raw_x.append(x_str);
        }
        return true;
    }
    if field_key == "k" {
        let k_str = json::read_string(reader, scratch);
        if k_str.len <= raw_k.cap {
            raw_k.clear();
            raw_k.append(k_str);
        }
        return true;
    }
    return false;
}

fn parse_jwk_key_field(
    field_key: const u8[:],
    reader: json::Reader&,
    scratch: u8[>..]&,
    raw_x: u8[..128]&,
    raw_k: u8[..128]&,
    key_item: JwksKey&,
) {
    if parse_jwk_key_core_type(field_key, reader, scratch, key_item) {
        // Matched kty, crv, or alg
    } else if parse_jwk_key_ident(field_key, reader, scratch, key_item) {
        // Matched use or kid
    } else if parse_jwk_key_material(field_key, reader, scratch, raw_x, raw_k) {
        // Matched x or k
    } else {
        json::skip(reader);
    }
}

fn parse_jwk_key_fields(
    reader: json::Reader&,
    scratch: u8[>..]&,
    raw_x: u8[..128]&,
    raw_k: u8[..128]&,
    key_item: JwksKey&,
) {
    json::each_member(reader) { field_key =>
        scratch.clear();
        parse_jwk_key_field(field_key, reader, scratch, raw_x, raw_k, key_item);
    };
}

fn finalize_okp_key(raw_x: const u8[:], key_item: JwksKey&) -> bool {
    // RFC 8037 §2 & §3.1: OKP curve MUST be Ed25519 for EdDSA signatures
    guard key_item.crv[..] == "Ed25519" else { return false; }
    guard key_item.alg == JwtAlg.None || key_item.alg == JwtAlg.EdDSA else { return false; }
    guard raw_x.len > 0 else { return false; }
    var decoded_x: u8[>..] = [];
    guard core::base64url_decode(raw_x, decoded_x) else { return false; }
    guard decoded_x.len == ED25519_KEY_LEN else { return false; }
    for i in ED25519_KEY_LEN {
        key_item.public_key[i] = decoded_x[i];
    }
    key_item.valid = true;
    return true;
}

fn finalize_oct_key(raw_k: const u8[:], key_item: JwksKey&) -> bool {
    guard key_item.alg != JwtAlg.EdDSA else { return false; }
    guard raw_k.len > 0 else { return false; }
    var decoded_k: u8[>..] = [];
    guard core::base64url_decode(raw_k, decoded_k) else { return false; }
    // RFC 8725 §3.6 & RFC 7518 §3.2: Reject weak symmetric keys (< 128 bits / 16 bytes)
    guard decoded_k.len >= 16 && decoded_k.len <= HMAC_SHA512_MAC_LEN else { return false; }
    key_item.symmetric_key.clear();
    key_item.symmetric_key.append(decoded_k[..]);
    key_item.valid = true;
    return true;
}

fn finalize_jwk_key(
    raw_x: const u8[:],
    raw_k: const u8[:],
    key_item: JwksKey&,
) -> bool {
    return match key_item.kty {
        OKP => finalize_okp_key(raw_x, key_item),
        Oct => finalize_oct_key(raw_k, key_item),
    };
}

fn parse_single_jwk_element(
    reader: json::Reader&,
    scratch: u8[>..]&,
    out_jwks: Jwks&,
) {
    guard out_jwks.keys.len < out_jwks.keys.cap else {
        json::skip(reader);
        return;
    }

    var key_item = JwksKey { .. };
    var raw_x: u8[..128] = [];
    var raw_k: u8[..128] = [];

    parse_jwk_key_fields(reader, scratch, raw_x, raw_k, key_item);
    if finalize_jwk_key(raw_x[..], raw_k[..], key_item) {
        out_jwks.keys.push(key_item);
    }
}

// Parses an RFC 7517 JWKS JSON document into Jwks struct
fn parse_jwks_json(json_bytes: const u8[:], out_jwks: Jwks&) -> bool {
    out_jwks.keys.clear();
    var reader = json::reader(json_bytes);
    var scratch: u8[>..] = [];

    json::each_member(reader) { root_key =>
        if root_key == "keys" {
            json::each_element(reader) {
                parse_single_jwk_element(reader, scratch, out_jwks);
            };
        } else {
            json::skip(reader);
        }
    };

    return json::finish(reader) && out_jwks.keys.len > 0;
}

// ---- 3. Integrated JWKS JWT Verification -------------------------------------

fn resolve_jwks_key_index(jwks: const Jwks&, kid: const u8[:]) -> i64 {
    if kid.len > 0 {
        return find_key(jwks, kid);
    }
    if jwks.keys.len == 1 && jwks.keys[0].valid {
        return 0;
    }
    return -1;
}

fn is_kty_alg_compatible(kty: JwkKeyType, alg: JwtAlg) -> bool {
    return match kty {
        OKP => alg == JwtAlg.EdDSA,
        Oct => alg != JwtAlg.EdDSA && alg != JwtAlg.None,
    };
}

fn is_valid_key_use(use: const u8[:]) -> bool {
    return use.len == 0 || use == "sig";
}

fn validate_jwks_key_compatibility(
    key: const JwksKey&,
    header_alg: JwtAlg,
    allow_none: bool,
) -> JwtError {
    guard is_valid_key_use(key.use[..]) else {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.None && !allow_none {
        return JwtError.UnsupportedAlgorithm;
    }
    // RFC 8725 §3.2: Key Confusion Defense (Asymmetric vs Symmetric)
    guard is_kty_alg_compatible(key.kty, header_alg) else {
        return JwtError.AlgorithmMismatch;
    }
    if key.alg != JwtAlg.None && key.alg != header_alg {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}

fn verify_jwks_okp(
    token: const u8[:],
    key: const JwksKey&,
    options: const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header: JwtHeader&,
    out_claims: JwtClaims&,
) -> JwtError {
    guard out_header.alg == JwtAlg.EdDSA else {
        return JwtError.AlgorithmMismatch;
    }
    return verify_jwt_eddsa(token, key.public_key, options, now_unix_sec, out_header, out_claims);
}

fn verify_jwks_oct(
    token: const u8[:],
    key: const JwksKey&,
    options: const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header: JwtHeader&,
    out_claims: JwtClaims&,
) -> JwtError {
    guard out_header.alg != JwtAlg.EdDSA else {
        return JwtError.AlgorithmMismatch;
    }
    return verify_jwt_hmac(token, key.symmetric_key[..], options, now_unix_sec, out_header, out_claims);
}

fn dispatch_jwks_verification(
    token: const u8[:],
    key: const JwksKey&,
    options: const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header: JwtHeader&,
    out_claims: JwtClaims&,
) -> JwtError {
    let compat_err = validate_jwks_key_compatibility(key, out_header.alg, options.allow_none_alg);
    guard compat_err == JwtError.None else { return compat_err; }

    return match key.kty {
        OKP => verify_jwks_okp(token, key, options, now_unix_sec, out_header, out_claims),
        Oct => verify_jwks_oct(token, key, options, now_unix_sec, out_header, out_claims),
    };
}

// Verifies a JWT against a JWKS key set.
// Uses the `kid` in the JWT header to locate the active key and performs signature & claims validation.
fn verify(
    token: const u8[:],
    jwks: const Jwks&,
    options: const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header: JwtHeader&,
    out_claims: JwtClaims&,
) -> JwtError {
    let parse_err = parse_jwt_unverified(token, out_header, out_claims);
    guard parse_err == JwtError.None else { return parse_err; }

    let key_idx = resolve_jwks_key_index(jwks, out_header.kid[..]);
    guard key_idx >= 0 && key_idx < jwks.keys.len else {
        return JwtError.KeyNotFound;
    }

    let matched_key = jwks.keys[key_idx];
    guard matched_key.valid else { return JwtError.KeyNotFound; }

    return dispatch_jwks_verification(token, matched_key, options, now_unix_sec, out_header, out_claims);
}
