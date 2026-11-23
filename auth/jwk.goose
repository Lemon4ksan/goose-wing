// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// JSON Web Key (JWK) thumbprints (RFC 7638), zeroization, and key/algorithm compatibility checks (RFC 7517 / RFC 8725).
namespace auth;

import std;
import core;
import rfc.http;
import .types;
import .internal;

// RFC 7638 Section 3: JSON Web Key (JWK) Thumbprint - builds minimal canonical JWK JSON in lexicographical member order.
fn compute_canonical_jwk<B>(key: const JwksKey&, out: B&) -> bool {
    let is_okp = key.kty == JwkKeyType.OKP && key.crv[..] == "Ed25519" &&
        auth_internal::has_nonzero_byte_32(key.public_key);
    let is_ec = key.kty == JwkKeyType.EC && key.crv[..] == "P-256" &&
        auth_internal::is_valid_jwk_ec_p256_coords(key.ec_x[..], key.ec_y[..]);
    let is_oct = key.kty == JwkKeyType.Oct && key.symmetric_key.len >= 16;
    let is_rsa = key.kty == JwkKeyType.RSA &&
        auth_internal::is_canonical_jwk_rsa_params(key.rsa_n[..], key.rsa_e[..]);
    guard is_okp || is_ec || is_oct || is_rsa else { return false; }

    var committed = false;
    defer if !committed { out.resize(0); };
    out.clear();

    if is_okp {
        var x_b64: u8[..64] = [];
        core::base64url_encode(key.public_key[..], x_b64);
        guard out.try_append("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"") else { return false; }
        guard out.try_append(x_b64[..]) && out.try_append("\"}") else { return false; }
        committed = true;
        return true;
    }
    if is_ec {
        var x_b64: u8[..64] = [];
        var y_b64: u8[..64] = [];
        core::base64url_encode(key.ec_x[..], x_b64);
        core::base64url_encode(key.ec_y[..], y_b64);
        guard out.try_append("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"") else { return false; }
        guard out.try_append(x_b64[..]) && out.try_append("\",\"y\":\"") else { return false; }
        guard out.try_append(y_b64[..]) && out.try_append("\"}") else { return false; }
        committed = true;
        return true;
    }
    if is_oct {
        var k_b64: u8[..192] = [];
        defer core::secure_zeroize_slice(k_b64[..]);
        core::base64url_encode(key.symmetric_key[..], k_b64);
        guard out.try_append("{\"k\":\"") && out.try_append(k_b64[..]) else { return false; }
        guard out.try_append("\",\"kty\":\"oct\"}") else { return false; }
        committed = true;
        return true;
    }
    var n_b64: u8[..768] = [];
    var e_b64: u8[..16]  = [];
    core::base64url_encode(key.rsa_n[..], n_b64);
    core::base64url_encode(key.rsa_e[..], e_b64);
    guard out.try_append("{\"e\":\"") && out.try_append(e_b64[..]) else { return false; }
    guard out.try_append("\",\"kty\":\"RSA\",\"n\":\"") && out.try_append(n_b64[..]) else { return false; }
    guard out.try_append("\"}") else { return false; }
    committed = true;
    return true;
}

// RFC 7638 Section 3.1: JWK Thumbprint Computation - outputs 43-char unpadded Base64URL SHA-256 thumbprint into `out`.
fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool {
    var canonical: u8[..2048] = [];
    defer core::secure_zeroize_slice(canonical[..]);
    guard compute_canonical_jwk(key, canonical) else { return false; }

    let digest = core::sha256(canonical[..]);
    var encoded: u8[..64] = [];
    core::base64url_encode(digest[..], encoded);
    guard out.try_set(encoded[..]) else {
        out.resize(0);
        return false;
    }
    return true;
}

// Zeroizes symmetric and asymmetric key buffers in `key` and resets it to invalid default state.
fn zeroize_jwks_key(key: JwksKey&) {
    core::secure_zeroize_slice(key.symmetric_key[..]);
    core::secure_zeroize_32(key.public_key);
    core::secure_zeroize_slice(key.ec_x[..]);
    core::secure_zeroize_slice(key.ec_y[..]);
    core::secure_zeroize_slice(key.rsa_n[..]);
    core::secure_zeroize_slice(key.rsa_e[..]);
    core::secure_zeroize_slice(key.kid[..]);
    key = JwksKey { .. };
}

// RFC 7517 Section 4.2 / RFC 8725 Section 3.1: Validates JWK usage, key_ops, pinned alg, and kty compatibility.
fn validate_jwks_key_compatibility(key: const JwksKey&, header_alg: JwtAlg) -> JwtError {
    guard key.valid else { return JwtError.UnsupportedAlgorithm; }
    if header_alg == JwtAlg.None || header_alg == JwtAlg.Unknown || header_alg == JwtAlg.Unspecified {
        return JwtError.UnsupportedAlgorithm;
    }
    if key.use.len > 0 && key.use[..] != "sig" {
        return JwtError.UnsupportedAlgorithm;
    }
    if key.key_ops != 0 && (key.key_ops & JWK_OP_VERIFY) == 0 {
        return JwtError.UnsupportedAlgorithm;
    }
    if key.alg != JwtAlg.Unspecified && key.alg != header_alg {
        return JwtError.AlgorithmMismatch;
    }
    if key.kty == JwkKeyType.OKP && header_alg != JwtAlg.EdDSA {
        return JwtError.AlgorithmMismatch;
    }
    if key.kty == JwkKeyType.EC && header_alg != JwtAlg.ES256 {
        return JwtError.AlgorithmMismatch;
    }
    if key.kty == JwkKeyType.RSA && header_alg != JwtAlg.RS256 && header_alg != JwtAlg.PS256 {
        return JwtError.AlgorithmMismatch;
    }
    if key.kty == JwkKeyType.Oct && header_alg != JwtAlg.HS256 &&
        header_alg != JwtAlg.HS384 && header_alg != JwtAlg.HS512 {
        return JwtError.AlgorithmMismatch;
    }
    if key.kty == JwkKeyType.Unknown {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}
