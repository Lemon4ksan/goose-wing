// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal JWK JSON parsing, validation, and X.509 SPKI binding helpers.
namespace auth_internal;

import std;
import json;
import core from "..";
import rfc.http;
import .types;
import .internal;

fn jwk_key_type_to_string(kty: auth::JwkKeyType) -> const u8[:] {
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
fn parse_jwk_key_type(s: const u8[:]) -> auth::JwkKeyType {
    if s == "OKP" { return auth::JwkKeyType.OKP; }
    if s == "oct" { return auth::JwkKeyType.Oct; }
    if s == "EC" { return auth::JwkKeyType.EC; }
    if s == "RSA" { return auth::JwkKeyType.RSA; }
    return auth::JwkKeyType.Unknown;
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

inline fn classify_jwk_key_op(op: const u8[:]) -> u8, u8 {
    if op == "sign" { return 1, auth::JWK_OP_SIGN; }
    if op == "verify" { return 2, auth::JWK_OP_VERIFY; }
    if op == "encrypt" { return 4, auth::JWK_OP_ENCRYPT; }
    if op == "decrypt" { return 8, auth::JWK_OP_ENCRYPT; }
    if op == "wrapKey" { return 16, auth::JWK_OP_ENCRYPT; }
    if op == "unwrapKey" { return 32, auth::JWK_OP_ENCRYPT; }
    if op == "deriveKey" { return 64, auth::JWK_OP_ENCRYPT; }
    if op == "deriveBits" { return 128, auth::JWK_OP_ENCRYPT; }
    return 0, 0;
}

// Parses JWK "key_ops" array into key_item.key_ops bitmask (RFC 7517 §4.3).
//
// Example:
//   reader at "[\"sign\",\"verify\"]"
//   sets: key_item.key_ops = JWK_OP_SIGN | JWK_OP_VERIFY
inline fn parse_jwk_key_ops_array(reader: json::Reader&, key_item: auth::JwksKey&) {
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
    key_item:  auth::JwksKey&,
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
    raw_x5c_leaf: u8[..3072] = [],
    has_x5c:      bool       = false,
}

// RFC 7517 Section 4.7: "x5c" (X.509 Certificate Chain) Parameter - every chain entry must be valid PKIX DER
inline fn read_valid_x5c_cert_b64(reader: json::Reader&) -> bool {
    var b64_buf: u8[..3072] = [];
    var der_buf: u8[..2048] = [];
    guard core::read_json_string_into(reader, b64_buf) && b64_buf.len > 0 else { return false; }
    guard core::base64_decode(b64_buf[..], der_buf) && der_buf.len > 0 else { return false; }
    var cert = tls::ParsedCert { .. };
    return tls::parse_x509_certificate(der_buf[..], cert);
}

// Parses JWK "x5c" certificate chain array and extracts the leaf DER Base64 string (RFC 7517 §4.7).
//
// Example:
//   reader at "[\"MIIB...\"]"
//   sets: mat.has_x5c = true, mat.raw_x5c_leaf = "MIIB..."
inline fn parse_jwk_x5c_array(
    reader:   json::Reader&,
    mat:      JwkRawMaterial&,
    key_item: auth::JwksKey&,
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

inline fn read_jwk_material_field<B>(reader: json::Reader&, dst: B&, key_item: auth::JwksKey&) -> bool {
    if !core::read_json_string_into(reader, dst) || dst[..].index_of_byte('=') != -1 {
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
    key_item:  auth::JwksKey&,
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

fn finalize_okp_key(raw_x: const u8[:], key_item: auth::JwksKey&) -> bool {
    // RFC 8037 §2 & §3.1: OKP curve MUST be Ed25519 for EdDSA signatures
    guard key_item.crv[..] == "Ed25519" else { return false; }
    guard key_item.alg == auth::JwtAlg.Unspecified || key_item.alg == auth::JwtAlg.EdDSA else { return false; }
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

fn finalize_oct_key(raw_k: const u8[:], key_item: auth::JwksKey&) -> bool {
    let min_len = if key_item.alg == auth::JwtAlg.Unspecified {
        rfc::HMAC_SHA256_MAC_LEN
    } else {
        hmac_min_key_len(key_item.alg)
    };
    guard min_len > 0 && raw_k.len > 0 else { return false; }
    var decoded_k: u8[..128] = [];
    defer core::secure_zeroize_slice(decoded_k[..]);
    guard core::base64url_decode(raw_k, decoded_k) else { return false; }
    // RFC 7518 Section 3.2: HMAC with SHA-2 Functions - key must be at least hash output length
    guard decoded_k.len >= min_len && decoded_k.len <= key_item.symmetric_key.cap else {
        return false;
    }
    let _ = key_item.symmetric_key.try_set(decoded_k[..]);
    key_item.valid = true;
    return true;
}

fn finalize_ec_key(raw_x: const u8[:], raw_y: const u8[:], key_item: auth::JwksKey&) -> bool {
    // RFC 7518 §6.2: EC curve P-256 for ES256 signatures
    guard key_item.crv[..] == "P-256" else { return false; }
    guard key_item.alg == auth::JwtAlg.Unspecified || key_item.alg == auth::JwtAlg.ES256 else { return false; }
    guard raw_x.len > 0 && raw_y.len > 0 else { return false; }
    var decoded_x: u8[..64] = [];
    var decoded_y: u8[..64] = [];
    guard core::base64url_decode(raw_x, decoded_x) && core::base64url_decode(raw_y, decoded_y) else { return false; }
    guard is_valid_jwk_ec_p256_coords(decoded_x[..], decoded_y[..]) else { return false; }
    guard key_item.ec_x.try_set(decoded_x[..]) && key_item.ec_y.try_set(decoded_y[..]) else { return false; }
    key_item.valid = true;
    return true;
}

fn finalize_rsa_key(raw_n: const u8[:], raw_e: const u8[:], key_item: auth::JwksKey&) -> bool {
    // RFC 7518 §6.3: RSA modulus n and exponent e (Base64urlUInt without leading zero byte)
    guard key_item.alg == auth::JwtAlg.Unspecified ||
        key_item.alg == auth::JwtAlg.RS256 ||
        key_item.alg == auth::JwtAlg.PS256 else {
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

// RFC 7517 Section 4.7: "x5c" (X.509 Certificate Chain) Parameter - leaf DER must parse and match JWK key
inline fn validate_jwk_x5c_spki(leaf_der: const u8[:], key_item: const auth::JwksKey&) -> bool {
    guard key_item.kty != auth::JwkKeyType.Oct && key_item.kty != auth::JwkKeyType.Unknown else { return false; }
    var cert = tls::ParsedCert { .. };
    guard tls::parse_x509_certificate(leaf_der, cert) else { return false; }
    var spki_pub = tls::span_slice(leaf_der, cert.spki_pubkey);
    if spki_pub.len >= 2 && spki_pub[0] == 0 {
        spki_pub = spki_pub[1..];
    }
    if key_item.kty == auth::JwkKeyType.OKP {
        return spki_pub.len == 32 && core::ct_eq_bytes(spki_pub, key_item.public_key[..]);
    }
    if key_item.kty == auth::JwkKeyType.EC {
        guard spki_pub.len == 65 && spki_pub[0] == 0x04 else { return false; }
        let x_ok = core::ct_eq_bytes(spki_pub[1..33], key_item.ec_x[..]);
        return x_ok && core::ct_eq_bytes(spki_pub[33..65], key_item.ec_y[..]);
    }
    if key_item.kty == auth::JwkKeyType.RSA {
        let cert_n, cert_e, ok_rsa = core::parse_rsa_public_key_der(spki_pub);
        guard ok_rsa else { return false; }
        return core::ct_eq_bytes(cert_n, key_item.rsa_n[..]) && core::ct_eq_bytes(cert_e, key_item.rsa_e[..]);
    }
    return false;
}

inline fn validate_jwk_x5c_and_ops(mat: const JwkRawMaterial&, key_item: auth::JwksKey&) -> bool {
    // RFC 7517 §4.3: "use" and "key_ops" MUST NOT be used together unless consistent
    if key_item.use[..] == "sig" && (key_item.key_ops & auth::JWK_OP_ENCRYPT) != 0 {
        return false;
    }
    if key_item.use[..] == "enc" && (key_item.key_ops & (auth::JWK_OP_SIGN | auth::JWK_OP_VERIFY)) != 0 {
        return false;
    }
    if mat.has_x5c {
        var leaf_der: u8[..2048] = [];
        guard core::base64_decode(mat.raw_x5c_leaf[..], leaf_der) && leaf_der.len > 0 else {
            return false;
        }
        guard validate_jwk_x5c_spki(leaf_der[..], key_item) else { return false; }
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
