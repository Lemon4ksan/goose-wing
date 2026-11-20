// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal DPoP JWK parsing, signature verification, and thumbprint matching helpers.
namespace auth_internal;

import std;
import json;
import core from "..";
import rfc.http;
import .types;
import .internal;

const MAX_DPOP_PROOF_LEN: i64 = 4096;

var g_dpop_jti_seq: u64 = 0x853c49e6748fea9b;

// RFC 9449 Section 4.2: DPoP Proof JWT Syntax - Stateful entropy mixer for negligible collision probability.
inline fn next_dpop_entropy() -> u64 {
    g_dpop_jti_seq = g_dpop_jti_seq + 0x9e3779b97f4a7c15;
    return (clock_ns() as u64) ^ g_dpop_jti_seq;
}

fn validate_dpop_jwk_params(info: const auth::DPoPJwkInfo&) -> bool {
    let no_rsa = info.n.len == 0 && info.e.len == 0;
    let is_okp_shape = info.crv[..] == "Ed25519" && info.x.len > 0 && info.y.len == 0 && no_rsa;
    let is_ec_shape = info.crv[..] == "P-256" && info.x.len > 0 && info.y.len > 0 && no_rsa;
    let is_rsa_shape = info.crv.len == 0 && info.n.len > 0 && info.e.len > 0 && info.x.len == 0 && info.y.len == 0;
    if info.kty[..] == "OKP" {
        guard is_okp_shape && info.x[..].index_of_byte('=') == -1 else { return false; }
        var decoded_x: u8[..64] = [];
        return core::base64url_decode(info.x[..], decoded_x) && decoded_x.len == 32;
    }
    if info.kty[..] == "EC" {
        guard is_ec_shape else { return false; }
        guard info.x[..].index_of_byte('=') == -1 && info.y[..].index_of_byte('=') == -1 else { return false; }
        var decoded_x: u8[..64] = [];
        var decoded_y: u8[..64] = [];
        guard core::base64url_decode(info.x[..], decoded_x) else { return false; }
        guard core::base64url_decode(info.y[..], decoded_y) else { return false; }
        return is_valid_jwk_ec_p256_coords(decoded_x[..], decoded_y[..]);
    }
    if info.kty[..] == "RSA" {
        guard is_rsa_shape else { return false; }
        guard info.n[..].index_of_byte('=') == -1 && info.e[..].index_of_byte('=') == -1 else { return false; }
        var decoded_n: u8[..512] = [];
        var decoded_e: u8[..8]   = [];
        guard core::base64url_decode(info.n[..], decoded_n) else { return false; }
        guard core::base64url_decode(info.e[..], decoded_e) else { return false; }
        return is_canonical_jwk_rsa_params(decoded_n[..], decoded_e[..]);
    }
    return false;
}

// Reads a single JSON string JWK coordinate field into `dst` and tracks duplicates.
//
// Example:
//   reader at "\"base64url...\"", seen = false
//   sets seen = true, populates dst
fn parse_dpop_jwk_coord<B>(
    reader: json::Reader&,
    seen:   bool&,
    dst:    B&,
    valid:  bool&,
) {
    if seen { valid = false; }
    seen = true;
    if !core::read_json_string_into(reader, dst) || dst.len == 0 || dst[..].index_of_byte('=') != -1 {
        dst.clear();
        valid = false;
    }
}

// Parses and validates the JWK `"key_ops"` array for a DPoP public verification key (RFC 7517 §4.3).
//
// Example:
//   reader at "[\"verify\"]", seen = false, valid = true
//   sets: seen = true, valid = true
inline fn parse_dpop_jwk_key_ops(reader: json::Reader&, seen: bool&, valid: bool&) {
    if seen || json::peek(reader) != '[' {
        valid = false;
        json::skip(reader);
        return;
    }
    seen = true;
    var count: i64 = 0;
    json::each_element(reader) {
        count = core::add_sat_i64(count, 1);
        if json::peek(reader) != '"' {
            valid = false;
            json::skip(reader);
        } else {
            var op_buf: u8[..16] = [];
            if count > 1 || !core::read_json_string_into(reader, op_buf) || op_buf[..] != "verify" {
                valid = false;
            }
        }
    };
    if count != 1 { valid = false; }
}

// Dispatches a DPoP JWK coordinate or parameter member (`alg`, `crv`, `x`, `y`, `n`, `e`) to `parse_dpop_jwk_coord`.
//
// Example:
//   jwk_key = "crv", reader at "\"Ed25519\""
//   populates info.crv = "Ed25519", returns: true
inline fn parse_dpop_jwk_param_field(
    jwk_key:  const u8[:],
    reader:   json::Reader&,
    info:     auth::DPoPJwkInfo&,
    seen_alg: bool&,
    seen_crv: bool&,
    seen_x:   bool&,
    seen_y:   bool&,
    seen_n:   bool&,
    seen_e:   bool&,
) -> bool {
    if jwk_key == "alg" { parse_dpop_jwk_coord(reader, seen_alg, info.alg, info.valid); return true; }
    if jwk_key == "crv" { parse_dpop_jwk_coord(reader, seen_crv, info.crv, info.valid); return true; }
    if jwk_key == "x" { parse_dpop_jwk_coord(reader, seen_x, info.x, info.valid); return true; }
    if jwk_key == "y" { parse_dpop_jwk_coord(reader, seen_y, info.y, info.valid); return true; }
    if jwk_key == "n" { parse_dpop_jwk_coord(reader, seen_n, info.n, info.valid); return true; }
    if jwk_key == "e" { parse_dpop_jwk_coord(reader, seen_e, info.e, info.valid); return true; }
    return false;
}

inline fn record_dpop_extra_key(key: const u8[:], seen: SeenHeaderKey[..16]&, ok_flag: bool&, invert: bool = false) {
    var dup = is_header_key_present(key, seen[..]);
    if !dup {
        var item = SeenHeaderKey { .. };
        if !item.name.try_set(key) || !seen.try_push(item) {
            dup = true;
        }
    }
    if dup {
        ok_flag = invert;
    }
}

fn verify_dpop_jwk(reader: json::Reader&, info: auth::DPoPJwkInfo&) -> bool {
    info = auth::DPoPJwkInfo { valid: false, .. };
    guard json::peek(reader) == '{' else {
        json::skip(reader);
        return false;
    }
    info.valid = true;
    var seen_kty = false;
    var seen_use = false;
    var seen_ops = false;
    var seen_alg = false;
    var seen_crv = false;
    var seen_x = false;
    var seen_y = false;
    var seen_n = false;
    var seen_e = false;
    var seen_extra: SeenHeaderKey[..16] = [];

    json::each_member(reader) { jwk_key =>
        if jwk_key.contains('\\') {
            info.valid = false;
            json::skip(reader);
        } else if jwk_key == "d" || jwk_key == "p" || jwk_key == "q" ||
                  jwk_key == "dp" || jwk_key == "dq" || jwk_key == "qi" || jwk_key == "oth" || jwk_key == "k" {
            info.has_private_key = true;
            json::skip(reader);
        } else if jwk_key == "kty" {
            if seen_kty { info.valid = false; }
            seen_kty = true;
            var kty_buf: u8[..16] = [];
            let kty_read_ok = core::read_json_string_into(reader, kty_buf);
            let kty_val = kty_buf[..];
            let is_supported = kty_read_ok && (kty_val == "OKP" || kty_val == "EC" || kty_val == "RSA");
            info.kty_ok = is_supported;
            if !kty_read_ok {
                info.valid = false;
            } else if is_supported {
                let _ = info.kty.try_set(kty_val);
            } else if kty_val.eq_ascii_fold("oct") {
                info.has_private_key = true;
            }
        } else if jwk_key == "use" {
            if seen_use { info.valid = false; }
            seen_use = true;
            var use_buf: u8[..16] = [];
            if !core::read_json_string_into(reader, use_buf) || use_buf[..] != "sig" {
                info.valid = false;
            }
        } else if jwk_key == "key_ops" {
            parse_dpop_jwk_key_ops(reader, seen_ops, info.valid);
        } else if !parse_dpop_jwk_param_field(
            jwk_key, reader, info,
            seen_alg, seen_crv, seen_x, seen_y, seen_n, seen_e,
        ) {
            record_dpop_extra_key(jwk_key, seen_extra, info.valid, false);
            json::skip(reader);
        }
    };

    let params_ok = validate_dpop_jwk_params(info);
    let ok = info.valid && seen_kty && info.kty_ok && params_ok && !info.has_private_key;
    if !ok {
        info = auth::DPoPJwkInfo { valid: false, .. };
    }
    return ok;
}

fn is_dpop_alg_jwk_compatible(alg: const u8[:], info: const auth::DPoPJwkInfo&) -> bool {
    guard info.alg.len == 0 || info.alg[..] == alg else { return false; }
    if alg == "EdDSA" {
        return info.kty[..] == "OKP" && info.crv[..] == "Ed25519";
    }
    if alg == "ES256" {
        return info.kty[..] == "EC" && info.crv[..] == "P-256";
    }
    if alg == "RS256" || alg == "RS384" || alg == "RS512" ||
       alg == "PS256" || alg == "PS384" || alg == "PS512" {
        return info.kty[..] == "RSA";
    }
    return false;
}

// RFC 9449 §4.3: Checks whether algorithm is an allowed asymmetric digital signature algorithm.
fn is_asymmetric_dpop_alg(alg: const u8[:]) -> bool {
    return alg == "EdDSA" ||
           alg == "ES256" || alg == "ES384" || alg == "ES512" ||
           alg == "RS256" || alg == "RS384" || alg == "RS512" ||
           alg == "PS256" || alg == "PS384" || alg == "PS512";
}

struct DPoPHeaderScanState {
    valid_typ:  bool                = false,
    valid_alg:  bool                = false,
    seen_typ:   bool                = false,
    seen_alg:   bool                = false,
    seen_jwk:   bool                = false,
    had_dup:    bool                = false,
    has_crit:   bool                = false,
    seen_extra: SeenHeaderKey[..16] = [],
}

fn read_dpop_typ_member(reader: json::Reader&, st: DPoPHeaderScanState&) {
    if st.seen_typ { st.had_dup = true; }
    st.seen_typ = true;
    var typ_buf: u8[..32] = [];
    guard core::read_json_string_into(reader, typ_buf) else { return; }
    if typ_buf[..].eq_ascii_fold("dpop+jwt") || typ_buf[..].eq_ascii_fold("application/dpop+jwt") {
        st.valid_typ = true;
    }
}

fn read_dpop_header_member<B>(
    reader:       json::Reader&,
    key:          const u8[:],
    expected_alg: const u8[:],
    out_alg:      B&,
    out_jwk:      auth::DPoPJwkInfo&,
    st:           DPoPHeaderScanState&,
) {
    if key.contains_byte('\\') {
        st.had_dup = true;
        json::skip(reader);
        return;
    }
    if key == "crit" {
        st.has_crit = true;
        json::skip(reader);
        return;
    }
    if key == "typ" {
        read_dpop_typ_member(reader, st);
        return;
    }
    if key == "alg" {
        if st.seen_alg { st.had_dup = true; }
        st.seen_alg = true;
        if core::read_json_string_into(reader, out_alg) && is_asymmetric_dpop_alg(out_alg[..]) {
            if expected_alg.len == 0 || out_alg[..] == expected_alg {
                st.valid_alg = true;
            }
        }
        return;
    }
    if key == "jwk" {
        if st.seen_jwk { st.had_dup = true; }
        st.seen_jwk = true;
        if !verify_dpop_jwk(reader, out_jwk) { st.had_dup = true; }
        return;
    }
    record_dpop_extra_key(key, st.seen_extra, st.had_dup, true);
    json::skip(reader);
}

fn verify_dpop_signature(signing_input: const u8[:], sig_b64: const u8[:], pub_key: const u8[32]) -> bool {
    guard sig_b64.len > 0 && sig_b64.index_of_byte('=') == -1 else { return false; }
    var sig_bytes: u8[..128] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else { return false; }
    guard sig_bytes.len == 64 else { return false; }
    var sig_arr: u8[64] = [0; 64];
    for i in 64 { sig_arr[i] = sig_bytes[i]; }
    return core::ed25519_verify(pub_key, signing_input, sig_arr);
}

fn verify_dpop_signature_with_jwk(
    signing_input: const u8[:],
    sig_b64:       const u8[:],
    alg:           const u8[:],
    jwk_info:      const auth::DPoPJwkInfo&,
) -> bool {
    guard sig_b64.len > 0 && sig_b64.index_of_byte('=') == -1 else { return false; }
    if alg == "EdDSA" {
        guard jwk_info.kty[..] == "OKP" && jwk_info.crv[..] == "Ed25519" else { return false; }
        guard jwk_info.x[..].index_of_byte('=') == -1 else { return false; }
        var decoded_x: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
        var pub_arr: u8[32] = [0; 32];
        for i in 32 { pub_arr[i] = decoded_x[i]; }
        return verify_dpop_signature(signing_input, sig_b64, pub_arr);
    } else if alg == "ES256" {
        guard jwk_info.kty[..] == "EC" && jwk_info.crv[..] == "P-256" else { return false; }
        guard jwk_info.x[..].index_of_byte('=') == -1 && jwk_info.y[..].index_of_byte('=') == -1 else { return false; }
        var decoded_x: u8[..64] = [];
        var decoded_y: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
        guard core::base64url_decode(jwk_info.y[..], decoded_y) && decoded_y.len == 32 else { return false; }
        var pub_pt: u8[..65] = [];
        pub_pt.push(0x04);
        pub_pt.append(decoded_x[..]);
        pub_pt.append(decoded_y[..]);
        var sig_bytes: u8[..128] = [];
        guard core::base64url_decode(sig_b64, sig_bytes) && sig_bytes.len == 64 else { return false; }
        return core::ecdsa_p256_verify_p1363(pub_pt[..], signing_input, sig_bytes[..]);
    } else if alg == "RS256" || alg == "PS256" {
        guard jwk_info.kty[..] == "RSA" else { return false; }
        guard jwk_info.n[..].index_of_byte('=') == -1 && jwk_info.e[..].index_of_byte('=') == -1 else { return false; }
        var decoded_n: u8[..512] = [];
        var decoded_e: u8[..8]   = [];
        guard core::base64url_decode(jwk_info.n[..], decoded_n) else { return false; }
        guard core::base64url_decode(jwk_info.e[..], decoded_e) else { return false; }
        guard is_canonical_jwk_rsa_params(decoded_n[..], decoded_e[..]) else { return false; }
        var sig_bytes: u8[..512] = [];
        guard core::base64url_decode(sig_b64, sig_bytes) else { return false; }
        if alg == "RS256" {
            return core::rsa_pkcs1_sha256_verify(decoded_n[..], decoded_e[..], signing_input, sig_bytes[..]);
        }
        return core::rsa_pss_sha256_verify(decoded_n[..], decoded_e[..], signing_input, sig_bytes[..]);
    }
    return false;
}

// Parses a JSON numeric `iat` claim value from `reader` into `claims.iat` (RFC 9449 §4.2).
//
// Example:
//   reader at "1700000000}", claims = DPoPClaims { .. }, had_error = false
//   returns: claims.iat = 1700000000, claims.has_iat = true, had_error = false
inline fn parse_dpop_iat_field(reader: json::Reader&, claims: auth::DPoPClaims&, had_error: bool&) {
    let p = json::peek(reader);
    guard core::is_ascii_digit(p) else {
        json::skip(reader);
        had_error = true;
        return;
    }
    let val = json::read_int(reader);
    let next_ch = json::peek(reader);
    guard val > 0 && next_ch != '.' && next_ch != 'e' && next_ch != 'E' else {
        had_error = true;
        return;
    }
    claims.iat = val;
    claims.has_iat = true;
}

// Reads a JSON string claim into `dst`, flagging duplicates or empty/non-string values.
//
// Example:
//   reader at "\"GET\"", seen = false
//   sets dst = "GET", seen = true, had_error = false
inline fn parse_dpop_claim_str<B>(
    reader:    json::Reader&,
    dst:       B&,
    seen:      bool&,
    had_dup:   bool&,
    had_error: bool&,
) {
    if seen { had_dup = true; }
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

// RFC 9110 Section 9.1: Overview - HTTP method is a case-sensitive token (1*tchar)
inline fn is_valid_dpop_method(m: const u8[:]) -> bool {
    guard m.len > 0 else { return false; }
    for b in m {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

fn matches_dpop_jkt_thumbprint_jwk(
    jwk_info:     const auth::DPoPJwkInfo&,
    claims_jkt:   const u8[:],
    expected_jkt: const u8[:],
) -> bool {
    var canonical: u8[..1024] = [];
    if jwk_info.kty[..] == "OKP" {
        var decoded_x: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
        var x_b64: u8[..64] = [];
        core::base64url_encode(decoded_x[..], x_b64);
        canonical.append("{\"crv\":\"");
        canonical.append(jwk_info.crv[..]);
        canonical.append("\",\"kty\":\"OKP\",\"x\":\"");
        canonical.append(x_b64[..]);
        canonical.append("\"}");
    } else if jwk_info.kty[..] == "EC" {
        var decoded_x: u8[..64] = [];
        var decoded_y: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
        guard core::base64url_decode(jwk_info.y[..], decoded_y) && decoded_y.len == 32 else { return false; }
        var x_b64: u8[..64] = [];
        var y_b64: u8[..64] = [];
        core::base64url_encode(decoded_x[..], x_b64);
        core::base64url_encode(decoded_y[..], y_b64);
        canonical.append("{\"crv\":\"");
        canonical.append(jwk_info.crv[..]);
        canonical.append("\",\"kty\":\"EC\",\"x\":\"");
        canonical.append(x_b64[..]);
        canonical.append("\",\"y\":\"");
        canonical.append(y_b64[..]);
        canonical.append("\"}");
    } else if jwk_info.kty[..] == "RSA" {
        var decoded_n: u8[..512] = [];
        var decoded_e: u8[..8]   = [];
        guard core::base64url_decode(jwk_info.n[..], decoded_n) else { return false; }
        guard core::base64url_decode(jwk_info.e[..], decoded_e) else { return false; }
        guard is_canonical_jwk_rsa_params(decoded_n[..], decoded_e[..]) else { return false; }
        var e_b64: u8[..16]  = [];
        var n_b64: u8[..768] = [];
        core::base64url_encode(decoded_e[..], e_b64);
        core::base64url_encode(decoded_n[..], n_b64);
        canonical.append("{\"e\":\"");
        canonical.append(e_b64[..]);
        canonical.append("\",\"kty\":\"RSA\",\"n\":\"");
        canonical.append(n_b64[..]);
        canonical.append("\"}");
    } else {
        return false;
    }

    let digest = core::sha256(canonical[..]);
    var computed_jkt: u8[..64] = [];
    core::base64url_encode(digest[..], computed_jkt);

    if claims_jkt.len > 0 {
        guard claims_jkt.len == expected_jkt.len && core::ct_eq_bytes(claims_jkt, expected_jkt) else {
            return false;
        }
    }
    return core::ct_eq_bytes(computed_jkt[..], expected_jkt);
}

inline fn verify_dpop_eddsa_key_binding(key: const u8[:], jwk_info: const auth::DPoPJwkInfo&) -> bool {
    guard key.len == 32 && jwk_info.kty[..] == "OKP" && jwk_info.crv[..] == "Ed25519" else { return false; }
    guard jwk_info.x[..].index_of_byte('=') == -1 else { return false; }
    var jwk_pub: u8[..64] = [];
    guard core::base64url_decode(jwk_info.x[..], jwk_pub) && jwk_pub.len == 32 else { return false; }
    var key_seed: u8[32] = [0; 32];
    defer core::secure_zeroize_32(key_seed);
    for i in 32 { key_seed[i] = key[i]; }
    let derived_pub = core::ed25519_public_key(key_seed);
    return core::ct_eq_bytes(jwk_pub[..], key) || core::ct_eq_bytes(jwk_pub[..], derived_pub[..]);
}

inline fn verify_dpop_es256_key_binding(key: const u8[:], jwk_info: const auth::DPoPJwkInfo&) -> bool {
    guard jwk_info.kty[..] == "EC" && jwk_info.crv[..] == "P-256" else { return false; }
    guard jwk_info.x[..].index_of_byte('=') == -1 && jwk_info.y[..].index_of_byte('=') == -1 else { return false; }
    var decoded_x: u8[..64] = [];
    var decoded_y: u8[..64] = [];
    guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
    guard core::base64url_decode(jwk_info.y[..], decoded_y) && decoded_y.len == 32 else { return false; }
    if key.len == 65 {
        return key[0] == 0x04 &&
            core::ct_eq_bytes(key[1..33], decoded_x[..]) &&
            core::ct_eq_bytes(key[33..65], decoded_y[..]);
    }
    if key.len == 64 {
        return core::ct_eq_bytes(key[..32], decoded_x[..]) &&
            core::ct_eq_bytes(key[32..64], decoded_y[..]);
    }
    return false;
}
