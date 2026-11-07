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

// ---- JWK / JWKS Key Models -----------------------------------------------

enum JwkKeyType {
    Unknown,
    OKP,    // Octet Key Pair (RFC 8037: Ed25519)
    Oct,    // Symmetric Octet Sequence (RFC 7518: HMAC)
    EC,     // Elliptic Curve (RFC 7518: ECDSA P-256)
    RSA,    // RSA Key (RFC 7518: RSASSA-PKCS1-v1_5 / RSASSA-PSS)
}

fn jwk_key_type_to_string(kty: JwkKeyType) -> const u8[:] {
    return match kty {
        OKP => "OKP",
        Oct => "oct",
        EC => "EC",
        RSA => "RSA",
        Unknown => "unknown",
    };
}

// Parses a JWK "kty" parameter value into a JwkKeyType enum (RFC 7517 §4.1).
//
// Example:
//   s = "OKP"
//   returns: JwkKeyType.OKP
fn parse_jwk_key_type(s: const u8[:]) -> JwkKeyType {
    if s == "OKP" { return JwkKeyType.OKP; }
    if s == "oct" { return JwkKeyType.Oct; }
    if s == "EC" { return JwkKeyType.EC; }
    if s == "RSA" { return JwkKeyType.RSA; }
    return JwkKeyType.Unknown;
}

const JWK_OP_SIGN:    u8 = 1;
const JWK_OP_VERIFY:  u8 = 2;
const JWK_OP_ENCRYPT: u8 = 4;

struct JwksKey {
    kty:              JwkKeyType = JwkKeyType.Unknown,
    crv:              u8[..32]   = "",
    alg:              JwtAlg     = JwtAlg.Unspecified,
    use:              u8[..16]   = "",
    kid:              u8[..64]   = [],
    symmetric_key:    u8[..64]   = [],
    public_key:       u8[32]     = [0; 32],
    ec_x:             u8[..48]   = [],
    ec_y:             u8[..48]   = [],
    rsa_n:            u8[..512]  = [],
    rsa_e:            u8[..8]    = [],
    x5t_s256:         u8[..44]   = [],
    key_ops:          u8         = 0,
    valid:            bool       = false,
    has_invalid_type: bool       = false,
}

struct Jwks {
    keys: JwksKey[..16] = [],
}

// Registers an asymmetric Ed25519 public key in the key set
fn add_ed25519_key(
    jwks:    Jwks&,
    kid:     const u8[:],
    pub_key: const u8[32],
) -> bool {
    guard jwks.keys.len < jwks.keys.cap else { return false; }
    guard kid.len <= 64 else { return false; }
    var key = JwksKey {
        kty:        JwkKeyType.OKP,
        crv:        "Ed25519",
        alg:        JwtAlg.EdDSA,
        use:        "sig",
        public_key: pub_key,
        valid:      true,
        ..
    };
    key.kid.append(kid);
    jwks.keys.push(key);
    return true;
}

// Validates that (x, y) are 32-byte coordinates on the NIST P-256 curve (RFC 7518 §6.2.1).
inline fn is_valid_jwk_ec_p256_coords(x: const u8[:], y: const u8[:]) -> bool {
    guard x.len == 32 && y.len == 32 else { return false; }
    var pub_pt: u8[..65] = [];
    pub_pt.push(0x04);
    pub_pt.append(x);
    pub_pt.append(y);
    let _, ok_pt = core::decode_p256_public_key(pub_pt[..]);
    return ok_pt;
}

// Registers an asymmetric ECDSA P-256 public key in the key set (RFC 7518 §6.2).
fn add_es256_key(
    jwks: Jwks&,
    kid:  const u8[:],
    x:    const u8[:],
    y:    const u8[:],
) -> bool {
    guard jwks.keys.len < jwks.keys.cap else { return false; }
    guard kid.len <= 64 && is_valid_jwk_ec_p256_coords(x, y) else { return false; }
    var key = JwksKey {
        kty:   JwkKeyType.EC,
        crv:   "P-256",
        alg:   JwtAlg.ES256,
        use:   "sig",
        valid: true,
        ..
    };
    key.kid.append(kid);
    key.ec_x.append(x);
    key.ec_y.append(y);
    jwks.keys.push(key);
    return true;
}

// Validates RFC 7518 §2 & §6.3.1.1-6.3.1.2 minimal Base64urlUInt RSA modulus and public exponent.
inline fn is_canonical_jwk_rsa_params(n_be: const u8[:], e_be: const u8[:]) -> bool {
    guard n_be.len >= 64 && n_be.len <= 512 && e_be.len >= 1 && e_be.len <= 8 else { return false; }
    let n_last = core::sub_sat_i64(n_be.len, 1);
    guard (n_be[0] & 0x80) != 0 && (n_be[n_last] & 1) == 1 else { return false; }
    return e_be[0] != 0 && core::is_valid_rsa_public_exponent(e_be, n_be);
}

// Registers an asymmetric RSA public key in the key set (RFC 7518 §6.3).
fn add_rsa_key(
    jwks: Jwks&,
    kid:  const u8[:],
    alg:  JwtAlg,
    n_be: const u8[:],
    e_be: const u8[:],
) -> bool {
    guard jwks.keys.len < jwks.keys.cap else { return false; }
    guard kid.len <= 64 && is_canonical_jwk_rsa_params(n_be, e_be) else { return false; }
    guard alg == JwtAlg.Unspecified || alg == JwtAlg.RS256 || alg == JwtAlg.PS256 else { return false; }
    var key = JwksKey {
        kty:   JwkKeyType.RSA,
        alg:   alg,
        use:   "sig",
        valid: true,
        ..
    };
    key.kid.append(kid);
    key.rsa_n.append(n_be);
    key.rsa_e.append(e_be);
    jwks.keys.push(key);
    return true;
}

// Registers a symmetric HMAC secret key in the key set
fn add_symmetric_key(
    jwks:       Jwks&,
    kid:        const u8[:],
    alg:        JwtAlg,
    secret_key: const u8[:],
) -> bool {
    guard jwks.keys.len < jwks.keys.cap else { return false; }
    guard kid.len <= 64 else { return false; }
    guard secret_key.len >= 16 && secret_key.len <= 64 else { return false; }
    guard alg == JwtAlg.Unspecified || alg == JwtAlg.HS256 || alg == JwtAlg.HS384 || alg == JwtAlg.HS512 else {
        return false;
    }
    var key = JwksKey {
        kty:   JwkKeyType.Oct,
        crv:   "",
        alg:   alg,
        use:   "sig",
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

// ---- JWK Canonicalization & Thumbprint (RFC 7638 / RFC 8037) -------------

// Computes RFC 7638 / RFC 8037 Canonical JSON representation of a JWK:
// - Lexicographically sorted required members only
// - No whitespace
// - OKP (RFC 8037 §4): "crv", "kty", "x"
// - oct (RFC 7638 §3.2): "k", "kty"
// - EC  (RFC 7638 §3.2): "crv", "kty", "x", "y"
// - RSA (RFC 7638 §3.2): "e", "kty", "n"
// - Ignores optional members (alg, use, kid)
inline fn has_nonzero_byte_32(buf: const u8[32]) -> bool {
    var acc: u8 = 0;
    for b in buf { acc = acc | b; }
    return acc != 0;
}

fn compute_canonical_jwk<B>(key: const JwksKey&, out: B&) -> bool {
    let is_okp = key.kty == JwkKeyType.OKP && key.crv[..] == "Ed25519" && has_nonzero_byte_32(key.public_key);
    let is_oct = key.kty == JwkKeyType.Oct && key.symmetric_key.len >= 16;
    let is_ec_curve = key.kty == JwkKeyType.EC && key.crv[..] == "P-256";
    let is_ec = is_ec_curve && is_valid_jwk_ec_p256_coords(key.ec_x[..], key.ec_y[..]);
    let is_rsa = key.kty == JwkKeyType.RSA && is_canonical_jwk_rsa_params(key.rsa_n[..], key.rsa_e[..]);
    guard is_okp || is_oct || is_ec || is_rsa else { return false; }

    out.clear();
    var buf: u8[..1024] = [];
    if is_okp {
        buf.append("{\"crv\":\"");
        buf.append(key.crv[..]);
        buf.append("\",\"kty\":\"OKP\",\"x\":\"");
        var x_b64: u8[..64] = [];
        core::base64url_encode(key.public_key[..], x_b64);
        buf.append(x_b64[..]);
        buf.append("\"}");
    } else if is_oct {
        buf.append("{\"k\":\"");
        var k_b64: u8[..128] = [];
        core::base64url_encode(key.symmetric_key[..], k_b64);
        buf.append(k_b64[..]);
        core::secure_zeroize_slice(k_b64[..]);
        buf.append("\",\"kty\":\"oct\"}");
    } else if is_ec {
        buf.append("{\"crv\":\"");
        buf.append(key.crv[..]);
        buf.append("\",\"kty\":\"EC\",\"x\":\"");
        var x_b64: u8[..64] = [];
        core::base64url_encode(key.ec_x[..], x_b64);
        buf.append(x_b64[..]);
        buf.append("\",\"y\":\"");
        var y_b64: u8[..64] = [];
        core::base64url_encode(key.ec_y[..], y_b64);
        buf.append(y_b64[..]);
        buf.append("\"}");
    } else {
        buf.append("{\"e\":\"");
        var e_b64: u8[..16] = [];
        core::base64url_encode(key.rsa_e[..], e_b64);
        buf.append(e_b64[..]);
        buf.append("\",\"kty\":\"RSA\",\"n\":\"");
        var n_b64: u8[..768] = [];
        core::base64url_encode(key.rsa_n[..], n_b64);
        buf.append(n_b64[..]);
        buf.append("\"}");
    }
    let ok = out.try_set(buf[..]);
    core::secure_zeroize_slice(buf[..]);
    return ok;
}

// Computes the RFC 7638 JWK Thumbprint:
// SHA-256 hash of canonical JSON, base64url-encoded without padding.
fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool {
    out.clear();
    guard out.cap >= 43 else { return false; }
    var canonical: u8[..1024] = [];
    guard compute_canonical_jwk(key, canonical) else { return false; }
    let digest = core::sha256(canonical[..]);
    core::secure_zeroize_slice(canonical[..]);
    core::base64url_encode(digest[..], out);
    return true;
}

// ---- JWKS Serialization & Parsing (RFC 7517) ------------------------------

fn serialize_jwk_key<B>(k: const JwksKey&, out: B&) {
    out.append("{\"kty\":");
    core::format_json_string(out, jwk_key_type_to_string(k.kty));

    if k.kty == JwkKeyType.OKP {
        out.append(",\"crv\":");
        core::format_json_string(out, k.crv[..]);
        out.append(",\"x\":");
        var x_b64: u8[..64] = [];
        core::base64url_encode(k.public_key[..], x_b64);
        core::format_json_string(out, x_b64[..]);
    } else if k.kty == JwkKeyType.EC {
        out.append(",\"crv\":");
        core::format_json_string(out, k.crv[..]);
        out.append(",\"x\":");
        var x_b64: u8[..64] = [];
        core::base64url_encode(k.ec_x[..], x_b64);
        core::format_json_string(out, x_b64[..]);
        out.append(",\"y\":");
        var y_b64: u8[..64] = [];
        core::base64url_encode(k.ec_y[..], y_b64);
        core::format_json_string(out, y_b64[..]);
    } else if k.kty == JwkKeyType.RSA {
        out.append(",\"n\":");
        var n_b64: u8[..768] = [];
        core::base64url_encode(k.rsa_n[..], n_b64);
        core::format_json_string(out, n_b64[..]);
        out.append(",\"e\":");
        var e_b64: u8[..16] = [];
        core::base64url_encode(k.rsa_e[..], e_b64);
        core::format_json_string(out, e_b64[..]);
    } else {
        out.append(",\"k\":");
        var k_b64: u8[..128] = [];
        core::base64url_encode(k.symmetric_key[..], k_b64);
        core::format_json_string(out, k_b64[..]);
        core::secure_zeroize_slice(k_b64[..]);
    }

    if k.alg != JwtAlg.Unspecified && k.alg != JwtAlg.None && k.alg != JwtAlg.Unknown {
        out.append(",\"alg\":");
        core::format_json_string(out, jwt_alg_to_string(k.alg));
    }
    if k.use.len > 0 {
        out.append(",\"use\":");
        core::format_json_string(out, k.use[..]);
    }
    if k.kid.len > 0 {
        out.append(",\"kid\":");
        core::format_json_string(out, k.kid[..]);
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

inline fn read_nonempty_jwk_str<B>(reader: json::Reader&, dst: B&, invalid: bool&) {
    guard json::peek(reader) == '"' else {
        json::skip(reader);
        dst.clear();
        invalid = true;
        return;
    }
    if !core::read_json_string_into(reader, dst) || dst.len == 0 {
        dst.clear();
        invalid = true;
    }
}

// Parses core JWK type fields ("kty", "crv", "alg") from JSON reader (RFC 7517 §4).
//
// Example:
//   field_key = "kty", json string = "OKP"
//   sets: key_item.kty = OKP, returns: true
fn parse_jwk_key_core_type(
    field_key: const u8[:],
    reader:    json::Reader&,
    key_item:  JwksKey&,
) -> bool {
    if field_key == "kty" {
        var kty_buf: u8[..16] = [];
        if !core::read_json_string_into(reader, kty_buf) {
            key_item.kty = JwkKeyType.Unknown;
            key_item.has_invalid_type = true;
            return true;
        }
        key_item.kty = parse_jwk_key_type(kty_buf[..]);
        if key_item.kty == JwkKeyType.Unknown {
            key_item.has_invalid_type = true;
        }
        return true;
    }
    if field_key == "crv" {
        read_nonempty_jwk_str(reader, key_item.crv, key_item.has_invalid_type);
        return true;
    }
    if field_key == "alg" {
        var alg_buf: u8[..16] = [];
        if !core::read_json_string_into(reader, alg_buf) {
            key_item.alg = JwtAlg.Unknown;
            key_item.has_invalid_type = true;
            return true;
        }
        key_item.alg = parse_jwt_alg(alg_buf[..]);
        if key_item.alg == JwtAlg.Unknown || key_item.alg == JwtAlg.None {
            key_item.has_invalid_type = true;
        }
        return true;
    }
    return false;
}

// Parses JWK "key_ops" array into key_item.key_ops bitmask (RFC 7517 §4.3).
//
// Example:
//   reader at "[\"sign\",\"verify\"]"
//   sets: key_item.key_ops = JWK_OP_SIGN | JWK_OP_VERIFY
inline fn parse_jwk_key_ops_array(reader: json::Reader&, key_item: JwksKey&) {
    guard json::peek(reader) == '[' else {
        json::skip(reader);
        key_item.has_invalid_type = true;
        return;
    }
    var count: i64 = 0;
    json::each_element(reader) {
        count = core::add_sat_i64(count, 1);
        guard json::peek(reader) == '"' else {
            json::skip(reader);
            key_item.has_invalid_type = true;
            return;
        }
        var op_buf: u8[..16] = [];
        if !core::read_json_string_into(reader, op_buf) {
            key_item.has_invalid_type = true;
            return;
        }
        let op = op_buf[..];
        if op == "sign" {
            key_item.key_ops = key_item.key_ops | JWK_OP_SIGN;
        } else if op == "verify" {
            key_item.key_ops = key_item.key_ops | JWK_OP_VERIFY;
        } else if op == "encrypt" || op == "decrypt" || op == "wrapKey" || op == "unwrapKey" ||
                  op == "deriveKey" || op == "deriveBits" {
            key_item.key_ops = key_item.key_ops | JWK_OP_ENCRYPT;
        } else {
            key_item.has_invalid_type = true;
        }
    };
    if count == 0 {
        key_item.has_invalid_type = true;
    }
}

// Parses JWK identity and usage fields ("use", "kid", "key_ops", "x5t#S256") from JSON reader (RFC 7517 §4).
//
// Example:
//   field_key = "kid", json string = "key-1"
//   sets: key_item.kid = "key-1", returns: true
fn parse_jwk_key_ident(
    field_key: const u8[:],
    reader:    json::Reader&,
    key_item:  JwksKey&,
) -> bool {
    if field_key == "use" {
        read_nonempty_jwk_str(reader, key_item.use, key_item.has_invalid_type);
        return true;
    }
    if field_key == "kid" {
        read_nonempty_jwk_str(reader, key_item.kid, key_item.has_invalid_type);
        return true;
    }
    if field_key == "key_ops" {
        parse_jwk_key_ops_array(reader, key_item);
        return true;
    }
    if field_key == "x5t#S256" {
        read_nonempty_jwk_str(reader, key_item.x5t_s256, key_item.has_invalid_type);
        return true;
    }
    return false;
}

struct JwkRawMaterial {
    raw_x:        u8[..128]  = [],
    raw_y:        u8[..128]  = [],
    raw_k:        u8[..128]  = [],
    raw_n:        u8[..1024] = [],
    raw_e:        u8[..32]   = [],
    raw_x5c_leaf: u8[..2048] = [],
    has_x5c:      bool       = false,
}

// Validates a non-empty JSON string token in `reader` without copying its contents.
inline fn skip_nonempty_json_string(reader: json::Reader&) -> bool {
    let start = core::add_sat_i64(reader.pos, 1);
    let end, escaped = json::scan_string(reader.text, start);
    guard end > start && (!escaped || json::valid_escapes(reader.text, start, end)) else {
        json::fail(reader, "bad string");
        return false;
    }
    reader.pos = core::add_sat_i64(end, 1);
    return true;
}

// Parses JWK "x5c" certificate chain array and extracts the leaf DER Base64 string (RFC 7517 §4.7).
//
// Example:
//   reader at "[\"MIIB...\"]"
//   sets: mat.has_x5c = true, mat.raw_x5c_leaf = "MIIB..."
inline fn parse_jwk_x5c_array(
    reader:   json::Reader&,
    mat:      JwkRawMaterial&,
    key_item: JwksKey&,
) {
    guard json::peek(reader) == '[' else {
        json::skip(reader);
        key_item.has_invalid_type = true;
        return;
    }
    mat.has_x5c = true;
    var idx: i64 = 0;
    json::each_element(reader) {
        if json::peek(reader) != '"' {
            json::skip(reader);
            key_item.has_invalid_type = true;
        } else if idx == 0 {
            if !core::read_json_string_into(reader, mat.raw_x5c_leaf) || mat.raw_x5c_leaf.len == 0 {
                key_item.has_invalid_type = true;
            }
        } else if !skip_nonempty_json_string(reader) {
            key_item.has_invalid_type = true;
        }
        idx = core::add_sat_i64(idx, 1);
    };
    if idx == 0 {
        key_item.has_invalid_type = true;
    }
}

// Parses JWK cryptographic material fields ("x", "y", "k", "n", "e", "x5c") from JSON reader (RFC 7517 §4).
//
// Example:
//   field_key = "x", json string = "base64url..."
//   stores in mat.raw_x, returns: true
fn parse_jwk_key_material(
    field_key: const u8[:],
    reader:    json::Reader&,
    mat:       JwkRawMaterial&,
    key_item:  JwksKey&,
) -> bool {
    if field_key == "x" {
        if !core::read_json_string_into(reader, mat.raw_x) {
            mat.raw_x.clear();
            key_item.has_invalid_type = true;
        }
        return true;
    }
    if field_key == "y" {
        if !core::read_json_string_into(reader, mat.raw_y) {
            mat.raw_y.clear();
            key_item.has_invalid_type = true;
        }
        return true;
    }
    if field_key == "k" {
        if !core::read_json_string_into(reader, mat.raw_k) {
            mat.raw_k.clear();
            key_item.has_invalid_type = true;
        }
        return true;
    }
    if field_key == "n" {
        if !core::read_json_string_into(reader, mat.raw_n) {
            mat.raw_n.clear();
            key_item.has_invalid_type = true;
        }
        return true;
    }
    if field_key == "e" {
        if !core::read_json_string_into(reader, mat.raw_e) {
            mat.raw_e.clear();
            key_item.has_invalid_type = true;
        }
        return true;
    }
    if field_key == "x5c" {
        parse_jwk_x5c_array(reader, mat, key_item);
        return true;
    }
    return false;
}

// Dispatches a single JWK key object field to core, ident, or material parsers.
//
// Example:
//   field_key = "kty"
//   routes to parse_jwk_key_core_type
fn parse_jwk_key_field(
    field_key: const u8[:],
    reader:    json::Reader&,
    mat:       JwkRawMaterial&,
    key_item:  JwksKey&,
) {
    if field_key == "d" || field_key == "p" || field_key == "q" ||
       field_key == "dp" || field_key == "dq" || field_key == "qi" || field_key == "oth" {
        // RFC 7517 §4 & RFC 7518 §6.3.2.7: Public JWKs MUST NOT contain private key parameters
        key_item.has_invalid_type = true;
        json::skip(reader);
        return;
    }
    if parse_jwk_key_core_type(field_key, reader, key_item) {
        // Matched kty, crv, or alg
    } else if parse_jwk_key_ident(field_key, reader, key_item) {
        // Matched use or kid
    } else if parse_jwk_key_material(field_key, reader, mat, key_item) {
        // Matched x, y, k, n, or e
    } else {
        json::skip(reader);
    }
}

// Iterates all fields in a JWK JSON object and extracts key properties.
//
// Example:
//   reader positioned at {"kty":"OKP", ...}
//   populates key_item and mat
fn parse_jwk_key_fields(
    reader:   json::Reader&,
    mat:      JwkRawMaterial&,
    key_item: JwksKey&,
) {
    var seen_keys: SeenHeaderKey[..16] = [];
    json::each_member(reader) { field_key =>
        if field_key.contains('\\') || is_header_key_present(field_key, seen_keys[..]) {
            key_item.has_invalid_type = true;
        }
        if seen_keys.len < seen_keys.cap && field_key.len <= 64 {
            var item = SeenHeaderKey { .. };
            item.name.append(field_key);
            seen_keys.push(item);
        } else {
            key_item.has_invalid_type = true;
        }
        parse_jwk_key_field(field_key, reader, mat, key_item);
    };
}

fn finalize_okp_key(raw_x: const u8[:], key_item: JwksKey&) -> bool {
    // RFC 8037 §2 & §3.1: OKP curve MUST be Ed25519 for EdDSA signatures
    guard key_item.crv[..] == "Ed25519" else { return false; }
    guard key_item.alg == JwtAlg.Unspecified || key_item.alg == JwtAlg.EdDSA else { return false; }
    guard raw_x.len > 0 else { return false; }
    var decoded_x: u8[..64] = [];
    guard core::base64url_decode(raw_x, decoded_x) else { return false; }
    guard decoded_x.len == rfc::ED25519_KEY_LEN else { return false; }
    for i in rfc::ED25519_KEY_LEN {
        key_item.public_key[i] = decoded_x[i];
    }
    key_item.valid = true;
    return true;
}

fn finalize_oct_key(raw_k: const u8[:], key_item: JwksKey&) -> bool {
    guard key_item.alg == JwtAlg.Unspecified || key_item.alg == JwtAlg.HS256 ||
          key_item.alg == JwtAlg.HS384 || key_item.alg == JwtAlg.HS512 else { return false; }
    guard raw_k.len > 0 else { return false; }
    var decoded_k: u8[..128] = [];
    guard core::base64url_decode(raw_k, decoded_k) else { return false; }
    // RFC 8725 §3.6 & RFC 7518 §3.2: Reject weak symmetric keys (< 128 bits / 16 bytes)
    guard decoded_k.len >= 16 && decoded_k.len <= rfc::HMAC_SHA512_MAC_LEN else {
        core::secure_zeroize_slice(decoded_k[..]);
        return false;
    }
    key_item.symmetric_key.clear();
    key_item.symmetric_key.append(decoded_k[..]);
    core::secure_zeroize_slice(decoded_k[..]);
    key_item.valid = true;
    return true;
}

fn finalize_ec_key(raw_x: const u8[:], raw_y: const u8[:], key_item: JwksKey&) -> bool {
    // RFC 7518 §6.2: EC curve P-256 for ES256 signatures
    guard key_item.crv[..] == "P-256" else { return false; }
    guard key_item.alg == JwtAlg.Unspecified || key_item.alg == JwtAlg.ES256 else { return false; }
    guard raw_x.len > 0 && raw_y.len > 0 else { return false; }
    var decoded_x: u8[..64] = [];
    var decoded_y: u8[..64] = [];
    guard core::base64url_decode(raw_x, decoded_x) && core::base64url_decode(raw_y, decoded_y) else { return false; }
    guard is_valid_jwk_ec_p256_coords(decoded_x[..], decoded_y[..]) else { return false; }
    key_item.ec_x.clear();
    key_item.ec_x.append(decoded_x[..]);
    key_item.ec_y.clear();
    key_item.ec_y.append(decoded_y[..]);
    key_item.valid = true;
    return true;
}

fn finalize_rsa_key(raw_n: const u8[:], raw_e: const u8[:], key_item: JwksKey&) -> bool {
    // RFC 7518 §6.3: RSA modulus n and exponent e (Base64urlUInt without leading zero byte)
    guard key_item.alg == JwtAlg.Unspecified || key_item.alg == JwtAlg.RS256 || key_item.alg == JwtAlg.PS256 else {
        return false;
    }
    guard raw_n.len > 0 && raw_e.len > 0 else { return false; }
    var decoded_n: u8[..512] = [];
    var decoded_e: u8[..8]   = [];
    guard core::base64url_decode(raw_n, decoded_n) && core::base64url_decode(raw_e, decoded_e) else { return false; }
    guard is_canonical_jwk_rsa_params(decoded_n[..], decoded_e[..]) else { return false; }
    key_item.rsa_n.clear();
    key_item.rsa_n.append(decoded_n[..]);
    key_item.rsa_e.clear();
    key_item.rsa_e.append(decoded_e[..]);
    key_item.valid = true;
    return true;
}

inline fn validate_jwk_x5c_and_ops(mat: const JwkRawMaterial&, key_item: JwksKey&) -> bool {
    // RFC 7517 §4.3: "use" and "key_ops" MUST NOT be used together unless consistent
    if key_item.use[..] == "sig" && (key_item.key_ops & JWK_OP_ENCRYPT) != 0 {
        return false;
    }
    if key_item.use[..] == "enc" && (key_item.key_ops & (JWK_OP_SIGN | JWK_OP_VERIFY)) != 0 {
        return false;
    }
    if mat.has_x5c {
        var leaf_der: u8[..1536] = [];
        guard core::base64_decode(mat.raw_x5c_leaf[..], leaf_der) && leaf_der.len > 0 else {
            return false;
        }
        let digest = core::sha256(leaf_der[..]);
        var computed_x5t: u8[..44] = [];
        core::base64url_encode(digest[..], computed_x5t);
        if key_item.x5t_s256.len > 0 {
            guard core::ct_eq_bytes(computed_x5t[..], key_item.x5t_s256[..]) else {
                return false;
            }
        } else {
            let _ = key_item.x5t_s256.try_set(computed_x5t[..]);
        }
    }
    return true;
}

fn finalize_jwk_key(
    mat:      const JwkRawMaterial&,
    key_item: JwksKey&,
) -> bool {
    guard !key_item.has_invalid_type else { return false; }
    guard validate_jwk_x5c_and_ops(mat, key_item) else { return false; }
    return match key_item.kty {
        OKP => mat.raw_y.len == 0 && mat.raw_k.len == 0 && mat.raw_n.len == 0 && mat.raw_e.len == 0 &&
               finalize_okp_key(mat.raw_x[..], key_item),
        Oct => key_item.crv.len == 0 && mat.raw_x.len == 0 && mat.raw_y.len == 0 &&
               mat.raw_n.len == 0 && mat.raw_e.len == 0 && finalize_oct_key(mat.raw_k[..], key_item),
        EC => mat.raw_k.len == 0 && mat.raw_n.len == 0 && mat.raw_e.len == 0 &&
              finalize_ec_key(mat.raw_x[..], mat.raw_y[..], key_item),
        RSA => key_item.crv.len == 0 && mat.raw_x.len == 0 && mat.raw_y.len == 0 &&
               mat.raw_k.len == 0 && finalize_rsa_key(mat.raw_n[..], mat.raw_e[..], key_item),
        Unknown => false,
    };
}

// Parses and validates a single JWK key object from the "keys" JSON array.
//
// Example:
//   reader positioned at {"kty":"OKP", ...}
//   appends validated key to out_jwks, returns: true
fn parse_single_jwk_element(
    reader:   json::Reader&,
    out_jwks: Jwks&,
) -> bool {
    guard out_jwks.keys.len < out_jwks.keys.cap else {
        json::skip(reader);
        return false;
    }

    var key_item = JwksKey { .. };
    var mat = JwkRawMaterial { .. };

    parse_jwk_key_fields(reader, mat, key_item);
    let ok = finalize_jwk_key(mat, key_item);
    if ok {
        out_jwks.keys.push(key_item);
    }
    zeroize_jwks_key(key_item);
    core::secure_zeroize_slice(mat.raw_k[..]);
    return ok;
}

// Parses an RFC 7517 JWKS JSON document into Jwks struct.
//
// Example:
//   json_bytes = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}]}"
//   returns: true, out_jwks.keys.len = 1
fn parse_jwks_json(json_bytes: const u8[:], out_jwks: Jwks&) -> bool {
    out_jwks.keys.clear();
    var reader = json::reader(json_bytes);
    var seen_keys_root = false;
    var had_error = false;

    json::each_member(reader) { root_key =>
        if root_key.contains('\\') {
            had_error = true;
            json::skip(reader);
        } else if root_key == "keys" && !seen_keys_root && json::peek(reader) == '[' {
            seen_keys_root = true;
            json::each_element(reader) {
                let elem_ok = parse_single_jwk_element(reader, out_jwks);
                had_error = had_error || !elem_ok;
            };
        } else {
            if root_key == "keys" { had_error = true; }
            json::skip(reader);
        }
    };

    guard json::finish(reader) && !had_error && seen_keys_root && out_jwks.keys.len > 0 else {
        zeroize_jwks(out_jwks);
        return false;
    }
    return true;
}

// ---- Integrated JWKS JWT Verification -------------------------------------

fn resolve_jwks_key_index(jwks: const Jwks&, kid: const u8[:]) -> i64 {
    if kid.len > 0 {
        return find_key(jwks, kid);
    }
    if jwks.keys.len == 1 && jwks.keys[0].valid && jwks.keys[0].kid.len == 0 {
        return 0;
    }
    return -1;
}

fn is_kty_alg_compatible(kty: JwkKeyType, alg: JwtAlg) -> bool {
    return match kty {
        OKP => alg == JwtAlg.EdDSA,
        Oct => (alg == JwtAlg.HS256 || alg == JwtAlg.HS384 || alg == JwtAlg.HS512),
        EC => alg == JwtAlg.ES256,
        RSA => (alg == JwtAlg.RS256 || alg == JwtAlg.PS256),
        Unknown => false,
    };
}

fn is_valid_key_use(use: const u8[:]) -> bool {
    return use.len == 0 || use == "sig";
}

fn validate_jwks_key_compatibility(
    key:        const JwksKey&,
    header_alg: JwtAlg,
    allow_none: bool,
) -> JwtError {
    guard is_valid_key_use(key.use[..]) else {
        return JwtError.UnsupportedAlgorithm;
    }
    if key.key_ops != 0 && (key.key_ops & JWK_OP_VERIFY) == 0 {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.Unknown {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.None && !allow_none {
        return JwtError.UnsupportedAlgorithm;
    }
    // RFC 8725 §3.2: Key Confusion Defense (Asymmetric vs Symmetric)
    guard is_kty_alg_compatible(key.kty, header_alg) else {
        return JwtError.AlgorithmMismatch;
    }
    if key.alg != JwtAlg.Unspecified && key.alg != header_alg {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}

fn verify_jwks_ec_key(
    token:        const u8[:],
    key:          const JwksKey&,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var pub_pt: u8[..65] = [];
    pub_pt.push(0x04);
    pub_pt.append(key.ec_x[..]);
    pub_pt.append(key.ec_y[..]);
    return verify_jwt_es256(token, pub_pt[..], options, now_unix_sec, out_header, out_claims);
}

fn dispatch_jwks_verification(
    token:        const u8[:],
    key:          const JwksKey&,
    header_alg:   JwtAlg,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    let compat_err = validate_jwks_key_compatibility(key, header_alg, options.allow_none_alg);
    guard compat_err == JwtError.None else { return compat_err; }

    return match key.kty {
        OKP => verify_jwt_eddsa(token, key.public_key, options, now_unix_sec, out_header, out_claims),
        Oct => verify_jwt_hmac(token, key.symmetric_key[..], options, now_unix_sec, out_header, out_claims),
        EC => verify_jwks_ec_key(token, key, options, now_unix_sec, out_header, out_claims),
        RSA => verify_jwt_rsa(token, key.rsa_n[..], key.rsa_e[..], options, now_unix_sec, out_header, out_claims),
        Unknown => JwtError.KeyNotFound,
    };
}

// Verifies a JWT against a JWKS key set.
// Uses the `kid` in the JWT header to locate the active key and performs signature & claims validation.
fn verify(
    token:        const u8[:],
    jwks:         const Jwks&,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var temp_header = JwtHeader { .. };
    let parse_err = parse_jwt_header_only(token, temp_header);
    guard parse_err == JwtError.None else { return parse_err; }

    let key_idx = resolve_jwks_key_index(jwks, temp_header.kid[..]);
    guard key_idx >= 0 && key_idx < jwks.keys.len else {
        return JwtError.KeyNotFound;
    }

    let matched_key = jwks.keys[key_idx];
    guard matched_key.valid else { return JwtError.KeyNotFound; }

    return dispatch_jwks_verification(
        token, matched_key, temp_header.alg, options, now_unix_sec, out_header, out_claims,
    );
}

// Securely wipes cryptographic keys and invalidates a JWK key entry.
fn zeroize_jwks_key(key: JwksKey&) {
    core::secure_zeroize_slice(key.symmetric_key[..]);
    key.symmetric_key.clear();
    core::secure_zeroize_32(key.public_key);
    core::secure_zeroize_slice(key.ec_x[..]);
    key.ec_x.clear();
    core::secure_zeroize_slice(key.ec_y[..]);
    key.ec_y.clear();
    core::secure_zeroize_slice(key.rsa_n[..]);
    key.rsa_n.clear();
    core::secure_zeroize_slice(key.rsa_e[..]);
    key.rsa_e.clear();
    key.valid = false;
}

// Securely wipes all cryptographic keys in the JWKS set.
fn zeroize_jwks(jwks: Jwks&) {
    for i in jwks.keys.len {
        zeroize_jwks_key(jwks.keys[i]);
    }
    jwks.keys.clear();
}

// ---- SSRF Protection for Remote JWKS & OIDC Discovery (RFC 8725 §3.12) --

inline fn is_rfc1918_172(host: const u8[:]) -> bool {
    guard core::starts_with(host, "172.") && host.len >= 7 else { return false; }
    let c1 = host[4];
    let c2 = host[5];
    guard host[6] == '.' else { return false; }
    if c1 == '1' && c2 >= '6' && c2 <= '9' { return true; }
    if c1 == '2' && c2 >= '0' && c2 <= '9' { return true; }
    if c1 == '3' && (c2 == '0' || c2 == '1') { return true; }
    return false;
}

inline fn is_cgnat_100(host: const u8[:]) -> bool {
    guard core::starts_with(host, "100.") && host.len >= 7 else { return false; }
    let b4 = host[4];
    let b5 = host[5];
    let is_64_69 = b4 == '6' && (b5 >= '4' && b5 <= '9') && host[6] == '.';
    let is_70_99 = (b4 >= '7' && b4 <= '9') && (b5 >= '0' && b5 <= '9') && host[6] == '.';
    if is_64_69 || is_70_99 { return true; }
    guard b4 == '1' && host.len >= 8 && host[7] == '.' else { return false; }
    let is_100_119 = (b5 == '0' || b5 == '1') && (host[6] >= '0' && host[6] <= '9');
    let is_120_127 = b5 == '2' && (host[6] >= '0' && host[6] <= '7');
    return is_100_119 || is_120_127;
}

inline fn is_private_or_loopback_ipv4(host: const u8[:]) -> bool {
    if core::starts_with(host, "127.") { return true; }
    if core::starts_with(host, "10.") { return true; }
    if core::starts_with(host, "192.168.") { return true; }
    if core::starts_with(host, "169.254.") { return true; }
    if core::starts_with(host, "0.") { return true; }
    if is_rfc1918_172(host) { return true; }
    if is_cgnat_100(host) { return true; }
    return false;
}

inline fn is_forbidden_ipv6(host: const u8[:]) -> bool {
    if host == "::1" || host == "[::1]" || host == "::" || host == "[::]" { return true; }
    if host == "[0:0:0:0:0:0:0:1]" || host == "[0:0:0:0:0:0:0:0]" { return true; }
    if core::starts_with(host, "[::ffff:") || core::starts_with(host, "::ffff:") { return true; }
    if core::starts_with(host, "[0:0:0:0:0:ffff:") { return true; }
    let h = if core::starts_with(host, "[") && core::ends_with(host, "]") && host.len >= 2 {
        host[1..(host.len - 1)]
    } else {
        host
    };
    if core::starts_with(h, "fe8") || core::starts_with(h, "fe9") ||
       core::starts_with(h, "fea") || core::starts_with(h, "feb") {
        return true;
    }
    if core::starts_with(h, "fc") || core::starts_with(h, "fd") {
        return true;
    }
    if core::starts_with(h, "0::") || core::starts_with(h, "0:0:") || core::starts_with(h, "::") {
        return true;
    }
    return false;
}

inline fn is_all_digits_or_dots(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    for b in host {
        if b != '.' && (b < '0' || b > '9') {
            return false;
        }
    }
    return true;
}

inline fn has_hex_prefix(host: const u8[:]) -> bool {
    guard host.len >= 2 else { return false; }
    let limit = core::sub_sat_i64(host.len, 1);
    for i in limit {
        let next_i = core::add_sat_i64(i, 1);
        if host[i] == '0' && host[next_i] == 'x' { return true; }
    }
    return false;
}

inline fn is_non_canonical_ipv4(host: const u8[:]) -> bool {
    if has_hex_prefix(host) { return true; }
    guard is_all_digits_or_dots(host) else { return false; }

    var dot_cnt = 0;
    var octet_len = 0;
    var octet_val = 0;
    var first_zero = false;

    for b in host {
        if b == '.' {
            if octet_len == 0 || (octet_len > 1 && first_zero) || octet_len > 3 || octet_val > 255 { return true; }
            dot_cnt = core::add_sat_i64(dot_cnt, 1);
            octet_len = 0;
            octet_val = 0;
            first_zero = false;
        } else {
            if octet_len == 0 && b == '0' {
                first_zero = true;
            }
            octet_val = octet_val * 10 + (b - '0');
            octet_len = core::add_sat_i64(octet_len, 1);
        }
    }
    if octet_len == 0 || (octet_len > 1 && first_zero) || octet_len > 3 || octet_val > 255 { return true; }
    return dot_cnt != 3;
}

inline fn is_forbidden_internal_domain(host: const u8[:]) -> bool {
    if host == "localhost" || host == "metadata.google.internal" || host == "instance-data" { return true; }
    if core::ends_with(host, ".localhost") || core::ends_with(host, ".local") { return true; }
    if core::ends_with(host, ".internal") || core::ends_with(host, ".lan") { return true; }
    if core::ends_with(host, ".corp") { return true; }
    return false;
}

inline fn is_forbidden_internal_host(host: const u8[:]) -> bool {
    if is_forbidden_internal_domain(host) { return true; }
    if is_private_or_reserved_ip(host) { return true; }
    if is_forbidden_ipv6(host) { return true; }
    if is_non_canonical_ipv4(host) { return true; }
    return is_private_or_loopback_ipv4(host);
}

// Evaluates whether a remote JWKS URL is safe for network retrieval (RFC 8725 §3.12).
// Defends against SSRF, internal network scanning, cloud metadata exfiltration, and credential leaks.
//
// Example:
//   raw_url = "https://auth.example.com/.well-known/jwks.json"
//   returns: true
fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool {
    guard raw_url.len > 0 && raw_url.len <= 2048 else { return false; }
    let view, err = core::parse_url_view(raw_url);
    guard err == core::UrlParseError.None && view.valid else { return false; }
    guard view.scheme == "https" else { return false; }
    guard view.username.len == 0 && view.password.len == 0 else { return false; }
    guard view.port < 0 || view.port == 443 else { return false; }
    guard view.host.len > 0 && view.host.len <= 255 else { return false; }

    var norm_host: u8[..256] = [];
    core::to_lower_ascii(view.host, norm_host);
    while norm_host.len > 0 {
        let last_idx = core::sub_sat_i64(norm_host.len, 1);
        if norm_host[last_idx] == '.' {
            norm_host.pop();
        } else {
            break;
        }
    }
    guard norm_host.len > 0 else { return false; }
    return !is_forbidden_internal_host(norm_host[..]);
}
