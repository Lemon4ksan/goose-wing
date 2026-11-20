// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal JWKS JSON parsing, serialization, and verification dispatch helpers.
namespace auth_internal;

import std;
import json;
import core from "..";
import rfc.http;
import .types;
import .internal;
import .jwk_internal;
import .jwt_core;
import .jwt_internal;
import .jwt;
import .jwk;

// Parses JWK core type members ("kty", "crv", "alg") from JSON reader (RFC 7517 §4).
//
// Example:
//   field_key = "kty", reader at "\"OKP\""
//   sets: key_item.kty = JwkKeyType.OKP, returns: true
fn parse_jwk_key_core_type(
    field_key: const u8[:],
    reader:    json::Reader&,
    key_item:  auth::JwksKey&,
) -> bool {
    if field_key == "kty" {
        var buf: u8[..16] = [];
        read_nonempty_jwk_str(reader, buf, key_item.has_invalid_type);
        if !key_item.has_invalid_type {
            key_item.kty = parse_jwk_key_type(buf[..]);
            if key_item.kty == auth::JwkKeyType.Unknown { key_item.has_invalid_type = true; }
        }
        return true;
    }
    if field_key == "crv" {
        read_nonempty_jwk_str(reader, key_item.crv, key_item.has_invalid_type);
        return true;
    }
    if field_key == "alg" {
        var buf: u8[..16] = [];
        read_nonempty_jwk_str(reader, buf, key_item.has_invalid_type);
        if !key_item.has_invalid_type {
            key_item.alg = auth::parse_jwt_alg(buf[..]);
            if key_item.alg == auth::JwtAlg.Unknown || key_item.alg == auth::JwtAlg.None {
                key_item.has_invalid_type = true;
            }
        }
        return true;
    }
    return false;
}

// Parses one JWK JSON member, rejecting private key parameters ("d", "p", "q", "dp", "dq", "qi", "oth").
//
// Example:
//   field_key = "d", reader at "\"secret\""
//   sets: key_item.has_invalid_type = true
fn parse_jwk_key_field(
    field_key: const u8[:],
    reader:    json::Reader&,
    mat:       JwkRawMaterial&,
    key_item:  auth::JwksKey&,
) {
    if parse_jwk_key_core_type(field_key, reader, key_item) { return; }
    if parse_jwk_key_ident(field_key, reader, key_item) { return; }
    if parse_jwk_key_material(field_key, reader, mat, key_item) { return; }
    // RFC 7517 §4 / RFC 7518 §6.3.2: Reject private key parameters in public JWKS inputs.
    if field_key == "d" || field_key == "p" || field_key == "q" || field_key == "dp" ||
        field_key == "dq" || field_key == "qi" || field_key == "oth" {
        key_item.has_invalid_type = true;
    }
    json::skip(reader);
}

// Parses all members of a single JWK JSON object, rejecting escapes and duplicate/excess keys.
//
// Example:
//   reader at "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}"
//   populates `mat` and `key_item`
fn parse_jwk_key_fields(
    reader:   json::Reader&,
    mat:      JwkRawMaterial&,
    key_item: auth::JwksKey&,
) {
    var seen_fields: SeenHeaderKey[..16] = [];
    json::each_member(reader) { field_key =>
        var seen_item = SeenHeaderKey { .. };
        let valid_key = !field_key.contains('\\') &&
            !is_header_key_present(field_key, seen_fields[..]) &&
            seen_item.name.try_set(field_key) &&
            seen_fields.try_push(seen_item);
        if !valid_key {
            key_item.has_invalid_type = true;
            json::skip(reader);
        } else {
            parse_jwk_key_field(field_key, reader, mat, key_item);
        }
    };
}

fn finalize_jwk_key(mat: const JwkRawMaterial&, key_item: auth::JwksKey&) -> bool {
    guard !key_item.has_invalid_type else { return false; }
    var ok_kty = false;
    if key_item.kty == auth::JwkKeyType.OKP {
        ok_kty = finalize_okp_key(mat.raw_x[..], key_item);
    } else if key_item.kty == auth::JwkKeyType.Oct {
        ok_kty = finalize_oct_key(mat.raw_k[..], key_item);
    } else if key_item.kty == auth::JwkKeyType.EC {
        ok_kty = finalize_ec_key(mat.raw_x[..], mat.raw_y[..], key_item);
    } else if key_item.kty == auth::JwkKeyType.RSA {
        ok_kty = finalize_rsa_key(mat.raw_n[..], mat.raw_e[..], key_item);
    }
    guard ok_kty else { return false; }
    return validate_jwk_x5c_and_ops(mat, key_item);
}

inline fn append_jwk_kty_material<B>(k: const auth::JwksKey&, out: B&) -> bool {
    if k.kty == auth::JwkKeyType.OKP {
        var x_b64: u8[..64] = [];
        core::base64url_encode(k.public_key[..], x_b64);
        guard out.try_append(",\"crv\":") else { return false; }
        core::format_json_string(out, k.crv[..]);
        guard out.try_append(",\"x\":") else { return false; }
        core::format_json_string(out, x_b64[..]);
        return true;
    }
    if k.kty == auth::JwkKeyType.EC {
        var x_b64: u8[..64] = [];
        var y_b64: u8[..64] = [];
        core::base64url_encode(k.ec_x[..], x_b64);
        core::base64url_encode(k.ec_y[..], y_b64);
        guard out.try_append(",\"crv\":") else { return false; }
        core::format_json_string(out, k.crv[..]);
        guard out.try_append(",\"x\":") else { return false; }
        core::format_json_string(out, x_b64[..]);
        guard out.try_append(",\"y\":") else { return false; }
        core::format_json_string(out, y_b64[..]);
        return true;
    }
    if k.kty == auth::JwkKeyType.Oct {
        var k_b64: u8[..192] = [];
        defer core::secure_zeroize_slice(k_b64[..]);
        core::base64url_encode(k.symmetric_key[..], k_b64);
        guard out.try_append(",\"k\":") else { return false; }
        core::format_json_string(out, k_b64[..]);
        return true;
    }
    if k.kty == auth::JwkKeyType.RSA {
        var n_b64: u8[..768] = [];
        var e_b64: u8[..16]  = [];
        core::base64url_encode(k.rsa_n[..], n_b64);
        core::base64url_encode(k.rsa_e[..], e_b64);
        guard out.try_append(",\"n\":") else { return false; }
        core::format_json_string(out, n_b64[..]);
        guard out.try_append(",\"e\":") else { return false; }
        core::format_json_string(out, e_b64[..]);
        return true;
    }
    return false;
}

fn serialize_jwk_key<B>(k: const auth::JwksKey&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    guard out.try_append("{\"kty\":") else { return false; }
    core::format_json_string(out, jwk_key_type_to_string(k.kty));
    if k.kid.len > 0 {
        guard out.try_append(",\"kid\":") else { return false; }
        core::format_json_string(out, k.kid[..]);
    }
    if k.alg != auth::JwtAlg.Unspecified {
        guard out.try_append(",\"alg\":") else { return false; }
        core::format_json_string(out, jwt_alg_to_string(k.alg));
    }
    if k.use.len > 0 {
        guard out.try_append(",\"use\":") else { return false; }
        core::format_json_string(out, k.use[..]);
    }
    if k.x5t_s256.len > 0 {
        guard out.try_append(",\"x5t#S256\":") else { return false; }
        core::format_json_string(out, k.x5t_s256[..]);
    }
    guard append_jwk_kty_material(k, out) && out.try_push('}' as u8) else { return false; }
    committed = true;
    return true;
}

// Parses one element of the JWKS `"keys"` array into `out_jwks`.
//
// Example:
//   reader at "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}"
//   appends validated key to `out_jwks.keys`, returns: true
fn parse_single_jwk_element(
    reader:    json::Reader&,
    out_jwks:  auth::Jwks&,
    had_error: bool&,
) -> bool {
    guard json::peek(reader) == '{' else {
        json::skip(reader);
        had_error = true;
        return false;
    }
    var key_item = auth::JwksKey { .. };
    var mat = JwkRawMaterial { .. };
    defer auth::zeroize_jwks_key(key_item);
    defer core::secure_zeroize_slice(mat.raw_k[..]);
    parse_jwk_key_fields(reader, mat, key_item);
    if key_item.has_invalid_type {
        had_error = true;
        return false;
    }
    guard finalize_jwk_key(mat, key_item) else { return false; }
    if !out_jwks.keys.try_push(key_item) {
        had_error = true;
        return false;
    }
    return true;
}

// Parses the `"keys"` array inside a JWKS JSON document (RFC 7517 §5).
//
// Example:
//   reader at "[{...}]"
//   populates `out_jwks.keys` and sets `seen_keys_root = true`
inline fn parse_jwks_keys_array(
    reader:         json::Reader&,
    out_jwks:       auth::Jwks&,
    seen_keys_root: bool&,
    had_error:      bool&,
) {
    if seen_keys_root || json::peek(reader) != '[' {
        json::skip(reader);
        had_error = true;
        return;
    }
    seen_keys_root = true;
    json::each_element(reader) {
        let _ = parse_single_jwk_element(reader, out_jwks, had_error);
    };
}

fn verify_jwks_ec_key(
    token:        const u8[:],
    key:          const auth::JwksKey&,
    options:      const auth::JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   auth::JwtHeader&,
    out_claims:   auth::JwtClaims&,
) -> auth::JwtError {
    guard key.ec_x.len == 32 && key.ec_y.len == 32 else { return auth::JwtError.SignatureInvalid; }
    var pub_pt: u8[..65] = [];
    pub_pt.push(0x04);
    pub_pt.append(key.ec_x[..]);
    pub_pt.append(key.ec_y[..]);
    return auth::verify_jwt_es256(token, pub_pt[..], options, now_unix_sec, out_header, out_claims);
}

fn dispatch_jwks_verification(
    token:        const u8[:],
    key:          const auth::JwksKey&,
    header_alg:   auth::JwtAlg,
    options:      const auth::JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   auth::JwtHeader&,
    out_claims:   auth::JwtClaims&,
) -> auth::JwtError {
    let compat = auth::validate_jwks_key_compatibility(key, header_alg);
    guard compat == auth::JwtError.None else { return compat; }
    if key.kty == auth::JwkKeyType.OKP {
        return auth::verify_jwt_eddsa(token, key.public_key, options, now_unix_sec, out_header, out_claims);
    }
    if key.kty == auth::JwkKeyType.Oct {
        return auth::verify_jwt_hmac(token, key.symmetric_key[..], options, now_unix_sec, out_header, out_claims);
    }
    if key.kty == auth::JwkKeyType.EC {
        return verify_jwks_ec_key(token, key, options, now_unix_sec, out_header, out_claims);
    }
    if key.kty == auth::JwkKeyType.RSA {
        return auth::verify_jwt_rsa(token, key.rsa_n[..], key.rsa_e[..], options, now_unix_sec, out_header, out_claims);
    }
    return auth::JwtError.UnsupportedAlgorithm;
}
