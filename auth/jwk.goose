// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7517 JSON Web Key (JWK), RFC 7518 JWA key material validation,
// and RFC 7638 / RFC 8037 JWK Canonicalization and SHA-256 Thumbprint calculation.
namespace wing;

import std;
import json;
import core from "..";
import .jwt;

// ---- JWK Key Models ------------------------------------------------------

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

// Validates RFC 7518 §2 & §6.3.1.1-6.3.1.2 minimal Base64urlUInt RSA modulus and public exponent.
inline fn is_canonical_jwk_rsa_params(n_be: const u8[:], e_be: const u8[:]) -> bool {
    guard n_be.len >= 64 && n_be.len <= 512 && e_be.len >= 1 && e_be.len <= 8 else { return false; }
    let n_last = core::sub_sat_i64(n_be.len, 1);
    guard (n_be[0] & 0x80) != 0 && (n_be[n_last] & 1) == 1 else { return false; }
    return e_be[0] != 0 && core::is_valid_rsa_public_exponent(e_be, n_be);
}

// ---- JWK Canonicalization & Thumbprint (RFC 7638 / RFC 8037) -------------

inline fn has_nonzero_byte_32(buf: const u8[32]) -> bool {
    var acc: u8 = 0;
    for b in buf { acc = acc | b; }
    return acc != 0;
}

// Computes RFC 7638 / RFC 8037 Canonical JSON representation of a JWK:
// - Lexicographically sorted required members only
// - No whitespace
// - OKP (RFC 8037 §4): "crv", "kty", "x"
// - oct (RFC 7638 §3.2): "k", "kty"
// - EC  (RFC 7638 §3.2): "crv", "kty", "x", "y"
// - RSA (RFC 7638 §3.2): "e", "kty", "n"
// - Ignores optional members (alg, use, kid)
fn compute_canonical_jwk<B>(key: const JwksKey&, out: B&) -> bool {
    let is_okp = key.kty == JwkKeyType.OKP && key.crv[..] == "Ed25519" && has_nonzero_byte_32(key.public_key);
    let is_oct = key.kty == JwkKeyType.Oct && key.symmetric_key.len >= 16;
    let is_ec_curve = key.kty == JwkKeyType.EC && key.crv[..] == "P-256";
    let is_ec = is_ec_curve && is_valid_jwk_ec_p256_coords(key.ec_x[..], key.ec_y[..]);
    let is_rsa = key.kty == JwkKeyType.RSA && is_canonical_jwk_rsa_params(key.rsa_n[..], key.rsa_e[..]);
    guard is_okp || is_oct || is_ec || is_rsa else { return false; }

    out.clear();
    var buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(buf[..]);
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
        defer core::secure_zeroize_slice(k_b64[..]);
        core::base64url_encode(key.symmetric_key[..], k_b64);
        buf.append(k_b64[..]);
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
    return out.try_set(buf[..]);
}

// Computes the RFC 7638 JWK Thumbprint:
// SHA-256 hash of canonical JSON, base64url-encoded without padding.
fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool {
    out.clear();
    guard out.cap >= 43 else { return false; }
    var canonical: u8[..1024] = [];
    defer core::secure_zeroize_slice(canonical[..]);
    guard compute_canonical_jwk(key, canonical) else { return false; }
    let digest = core::sha256(canonical[..]);
    core::base64url_encode(digest[..], out);
    return true;
}

// ---- Single JWK Serialization & Parsing (RFC 7517) -----------------------

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

// Maps an RFC 7517 §4.3 `key_ops` value to `(unique_op_bit, role_bit)`.
inline fn classify_jwk_key_op(op: const u8[:]) -> u8, u8 {
    if op == "sign" { return 1, JWK_OP_SIGN; }
    if op == "verify" { return 2, JWK_OP_VERIFY; }
    if op == "encrypt" { return 4, JWK_OP_ENCRYPT; }
    if op == "decrypt" { return 8, JWK_OP_ENCRYPT; }
    if op == "wrapKey" { return 16, JWK_OP_ENCRYPT; }
    if op == "unwrapKey" { return 32, JWK_OP_ENCRYPT; }
    if op == "deriveKey" { return 64, JWK_OP_ENCRYPT; }
    if op == "deriveBits" { return 128, JWK_OP_ENCRYPT; }
    return 0, 0;
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
    var count:    i64 = 0;
    var seen_ops: u8  = 0;
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
        let spec_bit, role_bit = classify_jwk_key_op(op_buf[..]);
        if spec_bit == 0 || (seen_ops & spec_bit) != 0 {
            key_item.has_invalid_type = true;
        } else {
            seen_ops = seen_ops | spec_bit;
            key_item.key_ops = key_item.key_ops | role_bit;
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

// Validates a non-empty Base64 certificate string token in `reader` (RFC 7517 §4.7).
inline fn read_valid_x5c_cert_b64(reader: json::Reader&) -> bool {
    var b64_buf: u8[..2048] = [];
    var der_buf: u8[..2048] = [];
    return core::read_json_string_into(reader, b64_buf) && b64_buf.len > 0 &&
           core::base64_decode(b64_buf[..], der_buf) && der_buf.len > 0;
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
        } else if !read_valid_x5c_cert_b64(reader) {
            key_item.has_invalid_type = true;
        }
        idx = core::add_sat_i64(idx, 1);
    };
    if idx == 0 {
        key_item.has_invalid_type = true;
    }
}

inline fn read_jwk_material_field<B>(reader: json::Reader&, dst: B&, key_item: JwksKey&) -> bool {
    if !core::read_json_string_into(reader, dst) {
        dst.clear();
        key_item.has_invalid_type = true;
    }
    return true;
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
    if field_key == "x" { return read_jwk_material_field(reader, mat.raw_x, key_item); }
    if field_key == "y" { return read_jwk_material_field(reader, mat.raw_y, key_item); }
    if field_key == "k" { return read_jwk_material_field(reader, mat.raw_k, key_item); }
    if field_key == "n" { return read_jwk_material_field(reader, mat.raw_n, key_item); }
    if field_key == "e" { return read_jwk_material_field(reader, mat.raw_e, key_item); }
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
        var item = SeenHeaderKey { .. };
        if !item.name.try_set(field_key) || !seen_keys.try_push(item) {
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
    defer core::secure_zeroize_slice(decoded_k[..]);
    guard core::base64url_decode(raw_k, decoded_k) else { return false; }
    // RFC 8725 §3.6 & RFC 7518 §3.2: Reject weak symmetric keys (< 128 bits / 16 bytes)
    guard decoded_k.len >= 16 && decoded_k.len <= rfc::HMAC_SHA512_MAC_LEN else {
        return false;
    }
    let _ = key_item.symmetric_key.try_set(decoded_k[..]);
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
    guard key_item.ec_x.try_set(decoded_x[..]) && key_item.ec_y.try_set(decoded_y[..]) else { return false; }
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
    guard key_item.rsa_n.try_set(decoded_n[..]) && key_item.rsa_e.try_set(decoded_e[..]) else { return false; }
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
