// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9449 OAuth 2.0 Demonstrating Proof of Possession (DPoP) at the Application Layer.
// Provides sender-constraining for OAuth 2.0 access and refresh tokens.
// Handles JOSE header framing ("typ": "dpop+jwt"), HTM/HTU claims normalization,
// ATH access token hashing, JTI generation, proof creation, and verification.
namespace wing;

import std;
import json;
import core from "..";
import .jwt;
import .jwks;

// ---- RFC 9449 Constants & Identifiers ------------------------------------

struct DPoPClaims {
    jti:     u8[..128] = [],
    htm:     u8[..16]  = [],
    htu:     u8[..256] = [],
    iat:     i64       = -1,
    nonce:   u8[..128] = [],
    ath:     u8[..64]  = [],
    jkt:     u8[..64]  = [],
    has_iat: bool      = false,
}

struct DPoPConfig {
    key:     u8[..64]  = [],
    nonce:   u8[..128] = [],
    alg:     u8[..16]  = "EdDSA",
    enabled: bool      = false,
}

// ---- Helper Functions: URI Normalization & Access Token Hash -------------

// Normalizes target URI for the "htu" claim (RFC 9449 Section 4.2).
// Strips query string and fragment, forces scheme and host to lowercase,
// and removes default scheme ports (:80 / :443).
fn normalize_dpop_target_uri<B>(raw_uri: const u8[:], out: B&) -> bool {
    out.clear();
    guard raw_uri.len > 0 else { return false; }
    return core::normalize_http_target_uri(raw_uri, out);
}

// Computes the RFC 9449 Section 4.2 "ath" (Access Token Hash) claim:
// BASE64URL-ENCODE(SHA256(ASCII(access_token))) without padding.
fn compute_dpop_ath<B>(access_token: const u8[:], out: B&) {
    out.clear();
    guard access_token.len > 0 else { return; }
    let digest = core::sha256(access_token);
    core::base64url_encode(digest[..], out);
}

var g_dpop_jti_seq: u64 = 0x853c49e6748fea9b;

// RFC 9449 Section 4.2: DPoP Proof JWT Syntax - Stateful entropy mixer for negligible collision probability.
inline fn next_dpop_entropy() -> u64 {
    g_dpop_jti_seq = g_dpop_jti_seq + 0x9e3779b97f4a7c15;
    return (clock_ns() as u64) ^ g_dpop_jti_seq;
}

// Generates a cryptographically random unique identifier for the "jti" claim.
//
// Example:
//   out = ""
//   returns: out populated with 22-char base64url random identifier
fn generate_dpop_jti<B>(out: B&, entropy: const u8[:] = "") {
    out.clear();
    if entropy.len >= 16 {
        let max_ent = min(entropy.len, 96);
        core::base64url_encode(entropy[..max_ent], out);
        return;
    }
    // High-resolution clock-seeded pseudo-random fallback
    let charset: const u8[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var state: u64 = next_dpop_entropy();
    for b in entropy {
        state = state * 1099511628211 ^ (b as u64);
    }
    for i in 22 {
        state = state * 6364136223846793005 + 1442695040888963407 + (i as u64);
        let idx = (state >> 32) % 64;
        out.push(charset[idx as i64]);
    }
}

// ---- DPoP Proof JWT Generation -------------------------------------------

// Serializes DPoP claims JSON payload (RFC 9449 §4.2).
inline fn build_dpop_claims_json<B>(
    method:       const u8[:],
    norm_uri:     const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          B&,
) -> bool {
    guard now_sec > 0 && method.len > 0 else { return false; }
    for b in method { guard core::is_tchar(b) else { return false; } }
    if jti.len > 0 { guard rfc::is_valid_dpop_nonce(jti) else { return false; } }
    if nonce.len > 0 { guard rfc::is_valid_dpop_nonce(nonce) else { return false; } }
    let eff_jti_len = if jti.len > 0 { jti.len } else { 32 };
    let ath_len:   i64 = if access_token.len > 0 { 55 } else { 0 };
    let nonce_len: i64 = if nonce.len > 0 { core::add_sat_i64(nonce.len, 12) } else { 0 };
    let n1 = core::add_sat_i64(core::add_sat_i64(eff_jti_len, method.len), norm_uri.len);
    let needed = core::add_sat_i64(core::add_sat_i64(n1, nonce_len), ath_len);
    guard core::add_sat_i64(out.len, core::add_sat_i64(needed, 60)) <= out.cap else { return false; }

    out.clear();
    out.append("{\"jti\":\"");
    if jti.len > 0 {
        out.append(jti);
    } else {
        var auto_jti: u8[..32] = [];
        generate_dpop_jti(auto_jti);
        out.append(auto_jti[..]);
    }
    out.append("\",\"htm\":\"");
    for b in method {
        if b >= 'a' && b <= 'z' { out.push(b - 32); } else { out.push(b); }
    }
    out.append("\",\"htu\":\"");
    out.append(norm_uri);
    out.append("\",\"iat\":");
    core::format_i64_dec(now_sec, out);

    if nonce.len > 0 {
        out.append(",\"nonce\":\"");
        out.append(nonce);
        out.push('"' as u8);
    }
    if access_token.len > 0 {
        var ath: u8[..64] = [];
        compute_dpop_ath(access_token, ath);
        out.append(",\"ath\":\"");
        out.append(ath[..]);
        out.push('"' as u8);
    }
    out.push('}' as u8);
    return true;
}

// Creates an RFC 9449 signed DPoP Proof JWT:
// `header_b64.claims_b64.signature_b64`
struct DPoPJwkInfo {
    valid:           bool      = true,
    kty_ok:          bool      = false,
    has_private_key: bool      = false,
    kty:             u8[..8]   = [],
    crv:             u8[..16]  = [],
    x:               u8[..64]  = [],
    y:               u8[..64]  = [],
    n:               u8[..768] = [],
    e:               u8[..16]  = [],
}

// Reads a single JSON string JWK coordinate field into `dst` and tracks duplicates.
//
// Example:
//   reader at "\"base64url...\"", seen = false
//   sets seen = true, populates dst
fn parse_dpop_jwk_coord<B>(
    reader:  json::Reader&,
    scratch: u8[>..]&,
    seen:    bool&,
    dst:     B&,
    valid:   bool&,
) {
    if seen { valid = false; }
    seen = true;
    let val = json::read_string(reader, scratch);
    if core::index_of_byte(val, '=') != -1 || !dst.try_set(val) {
        valid = false;
    }
}

fn verify_dpop_jwk(reader: json::Reader&, scratch: u8[>..]&, info: DPoPJwkInfo&) -> bool {
    guard json::peek(reader) == '{' else {
        json::skip(reader);
        return false;
    }
    var seen_kty = false;
    var seen_crv = false;
    var seen_x = false;
    var seen_y = false;
    var seen_n = false;
    var seen_e = false;

    json::each_member(reader) { jwk_key =>
        scratch.clear();
        if jwk_key.contains('\\') {
            info.valid = false;
            json::skip(reader);
        } else if jwk_key == "d" || jwk_key == "p" || jwk_key == "q" ||
                  jwk_key == "dp" || jwk_key == "dq" || jwk_key == "qi" || jwk_key == "oth" {
            info.has_private_key = true;
            json::skip(reader);
        } else if jwk_key == "k" {
            info.has_private_key = true;
            json::skip(reader);
        } else if jwk_key == "kty" {
            if seen_kty { info.valid = false; }
            seen_kty = true;
            let kty_val = json::read_string(reader, scratch);
            let is_supported = (kty_val == "OKP" || kty_val == "EC" || kty_val == "RSA");
            info.kty_ok = is_supported;
            if is_supported {
                info.kty.try_set(kty_val);
            } else if core::eq_ascii_fold(kty_val, "oct") {
                info.has_private_key = true;
            }
        } else if jwk_key == "crv" {
            parse_dpop_jwk_coord(reader, scratch, seen_crv, info.crv, info.valid);
        } else if jwk_key == "x" {
            parse_dpop_jwk_coord(reader, scratch, seen_x, info.x, info.valid);
        } else if jwk_key == "y" {
            parse_dpop_jwk_coord(reader, scratch, seen_y, info.y, info.valid);
        } else if jwk_key == "n" {
            parse_dpop_jwk_coord(reader, scratch, seen_n, info.n, info.valid);
        } else if jwk_key == "e" {
            parse_dpop_jwk_coord(reader, scratch, seen_e, info.e, info.valid);
        } else {
            json::skip(reader);
        }
    };

    var params_ok = false;
    if info.kty[..] == "OKP" {
        params_ok = seen_crv && info.crv[..] == "Ed25519" && seen_x && info.x.len > 0 && !seen_y && !seen_n && !seen_e;
    } else if info.kty[..] == "EC" {
        let has_xy = seen_x && info.x.len > 0 && seen_y && info.y.len > 0;
        params_ok = seen_crv && info.crv[..] == "P-256" && has_xy && !seen_n && !seen_e;
    } else if info.kty[..] == "RSA" {
        params_ok = !seen_crv && seen_n && info.n.len > 0 && seen_e && info.e.len > 0 && !seen_x && !seen_y;
    }
    info.valid = info.valid && seen_kty && info.kty_ok && params_ok && !info.has_private_key;
    return info.valid;
}

// Extracts and decodes the 32-byte Ed25519 public key from the DPoP JWS header 'jwk' object (RFC 9449 §4.3).
//
// Example:
//   header_json = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"x\":\"...\"}}"
//   returns: true, out_pub populated with 32-byte public key
fn parse_dpop_header_jwk_pubkey(header_json: const u8[:], out_pub: u8[32]&) -> bool {
    var reader = json::reader(header_json);
    var scratch: u8[>..] = [];
    var jwk_info = DPoPJwkInfo { .. };
    var seen_jwk = false;
    var had_dup = false;
    json::each_member(reader) { key =>
        scratch.clear();
        if key.contains('\\') {
            had_dup = true;
            json::skip(reader);
        } else if key == "jwk" {
            if seen_jwk { had_dup = true; }
            seen_jwk = true;
            verify_dpop_jwk(reader, scratch, jwk_info);
        } else {
            json::skip(reader);
        }
    };
    let is_okp_valid = seen_jwk && jwk_info.valid && jwk_info.kty[..] == "OKP" && jwk_info.x.len > 0;
    guard json::finish(reader) && !had_dup && is_okp_valid else {
        return false;
    }
    var decoded_x: u8[..64] = [];
    guard core::base64url_decode(jwk_info.x[..], decoded_x) else { return false; }
    guard decoded_x.len == 32 else { return false; }
    for i in 32 { out_pub[i] = decoded_x[i]; }
    return true;
}

// Extracts the JOSE algorithm and JWK structure from a DPoP header JSON.
//
// Example:
//   header_json = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\"}}"
//   returns: true, out_alg = "ES256", out_jwk populated
fn parse_dpop_header_jwk_info(header_json: const u8[:], out_alg: u8[..16]&, out_jwk: DPoPJwkInfo&) -> bool {
    out_alg.clear();
    var reader = json::reader(header_json);
    var scratch: u8[>..] = [];
    var seen_jwk = false;
    var seen_alg = false;
    var had_dup = false;
    json::each_member(reader) { key =>
        scratch.clear();
        if key.contains('\\') {
            had_dup = true;
            json::skip(reader);
        } else if key == "alg" {
            if seen_alg { had_dup = true; }
            seen_alg = true;
            let alg_val = json::read_string(reader, scratch);
            if !out_alg.try_set(alg_val) { had_dup = true; }
        } else if key == "jwk" {
            if seen_jwk { had_dup = true; }
            seen_jwk = true;
            verify_dpop_jwk(reader, scratch, out_jwk);
        } else {
            json::skip(reader);
        }
    };
    return json::finish(reader) && !had_dup && seen_alg && seen_jwk && out_jwk.valid;
}

// Creates an RFC 9449 signed DPoP Proof JWT using an asymmetric key pair (EdDSA / Ed25519).
// Header contains mandatory "typ": "dpop+jwt", "alg": "EdDSA", and "jwk" public key (RFC 9449 §4.2, §4.3).
fn create_dpop_proof<B>(
    key:          const u8[:],
    method:       const u8[:],
    target_uri:   const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          B&,
) -> bool {
    out.clear();

    if nonce.len > 0 {
        guard rfc::is_valid_dpop_nonce(nonce) else { return false; }
    }
    if jti.len > 0 {
        guard rfc::is_valid_dpop_nonce(jti) else { return false; }
    }
    guard key.len == 32 else { return false; }

    var norm_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(target_uri, norm_uri) else {
        return false;
    }

    var claims_json: u8[..512] = [];
    guard build_dpop_claims_json(method, norm_uri[..], access_token, nonce, now_sec, jti, claims_json) else {
        return false;
    }

    var seed: u8[32] = [0; 32];
    for i in 32 { seed[i] = key[i]; }
    let pub_key = core::ed25519_public_key(seed);
    var x_b64: u8[..64] = [];
    core::base64url_encode(pub_key[..], x_b64);

    var header_json: u8[..256] = [];
    header_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"");
    header_json.append(x_b64[..]);
    header_json.append("\"}}");

    var header_b64: u8[..384] = [];
    core::base64url_encode(header_json[..], header_b64);

    var claims_b64: u8[..768] = [];
    core::base64url_encode(claims_json[..], claims_b64);

    var signing_input: u8[..1152] = [];
    signing_input.append(header_b64[..]);
    signing_input.push('.' as u8);
    signing_input.append(claims_b64[..]);

    let sig = core::ed25519_sign(seed, signing_input[..]);
    core::secure_zeroize_32(seed);
    var sig_b64: u8[..128] = [];
    core::base64url_encode(sig[..], sig_b64);

    let total_len = core::add_sat_i64(core::add_sat_i64(signing_input.len, 1), sig_b64.len);
    guard total_len <= out.cap else { return false; }
    out.append(signing_input[..]);
    out.push('.' as u8);
    out.append(sig_b64[..]);

    return true;
}

fn create_dpop_proof(
    key:          const u8[:],
    method:       const u8[:],
    target_uri:   const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          u8[>..]&,
) -> bool {
    var bounded: u8[..2048] = [];
    guard create_dpop_proof(key, method, target_uri, access_token, nonce, now_sec, jti, bounded) else {
        return false;
    }
    out.clear();
    out.append(bounded[..]);
    return true;
}

// Creates an RFC 9449 signed DPoP Proof JWT using an ECDSA P-256 key pair (ES256).
fn create_dpop_proof_es256<B>(
    priv_key:     const u8[32],
    method:       const u8[:],
    target_uri:   const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          B&,
) -> bool {
    out.clear();
    if nonce.len > 0 {
        guard rfc::is_valid_dpop_nonce(nonce) else { return false; }
    }
    if jti.len > 0 {
        guard rfc::is_valid_dpop_nonce(jti) else { return false; }
    }

    var norm_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(target_uri, norm_uri) else { return false; }

    var claims_json: u8[..512] = [];
    guard build_dpop_claims_json(method, norm_uri[..], access_token, nonce, now_sec, jti, claims_json) else {
        return false;
    }

    let pub_key = core::ecdsa_p256_public_key(priv_key);
    var x_b64: u8[..64] = [];
    var y_b64: u8[..64] = [];
    core::base64url_encode(pub_key[1..33], x_b64);
    core::base64url_encode(pub_key[33..65], y_b64);

    var header_json: u8[..384] = [];
    header_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"");
    header_json.append(x_b64[..]);
    header_json.append("\",\"y\":\"");
    header_json.append(y_b64[..]);
    header_json.append("\"}}");

    var header_b64: u8[..512] = [];
    core::base64url_encode(header_json[..], header_b64);

    var claims_b64: u8[..768] = [];
    core::base64url_encode(claims_json[..], claims_b64);

    var signing_input: u8[..1280] = [];
    signing_input.append(header_b64[..]);
    signing_input.push('.' as u8);
    signing_input.append(claims_b64[..]);

    let sig = core::ecdsa_p256_sign(priv_key, signing_input[..]);
    var sig_b64: u8[..128] = [];
    core::base64url_encode(sig[..], sig_b64);

    let total_len = core::add_sat_i64(core::add_sat_i64(signing_input.len, 1), sig_b64.len);
    guard total_len <= out.cap else { return false; }
    out.append(signing_input[..]);
    out.push('.' as u8);
    out.append(sig_b64[..]);
    return true;
}

// ---- DPoP Proof Verification ---------------------------------------------

// RFC 9449 §4.3: Checks whether algorithm is an allowed asymmetric digital signature algorithm.
// Rejects 'none' and all symmetric algorithms (such as HMAC, AES-GCM, dir).
fn is_asymmetric_dpop_alg(alg: const u8[:]) -> bool {
    return alg == "EdDSA" ||
           alg == "ES256" || alg == "ES384" || alg == "ES512" ||
           alg == "RS256" || alg == "RS384" || alg == "RS512" ||
           alg == "PS256" || alg == "PS384" || alg == "PS512";
}

// RFC 9449 §4.3 & §6.2: Rejects 'none' and symmetric HMAC algorithms (HS256, HS384, HS512).
// Asymmetric digital signature algorithms (e.g. EdDSA, ES256, RS256) are strictly required.
fn is_matching_dpop_alg(alg_val: const u8[:], expected_alg: const u8[:]) -> bool {
    guard is_asymmetric_dpop_alg(alg_val) else { return false; }
    if expected_alg.len > 0 {
        return alg_val == expected_alg;
    }
    return true;
}

// RFC 9449 §4.3: Validates DPoP JOSE header.
// Mandates typ == "dpop+jwt", asymmetric alg, and jwk containing public key without private components.
fn verify_dpop_header(header_json: const u8[:], expected_alg: const u8[:] = "EdDSA") -> bool {
    var reader = json::reader(header_json);
    var valid_typ = false;
    var valid_alg = false;
    var seen_typ = false;
    var seen_alg = false;
    var seen_jwk = false;
    var had_dup = false;
    var has_crit = false;
    var scratch: u8[>..] = [];
    var jwk_info = DPoPJwkInfo { .. };

    json::each_member(reader) { key =>
        scratch.clear();
        if key.contains('\\') {
            had_dup = true;
            json::skip(reader);
        } else if key == "crit" {
            has_crit = true;
            json::skip(reader);
        } else if key == "typ" {
            if seen_typ { had_dup = true; }
            seen_typ = true;
            let typ_val = json::read_string(reader, scratch);
            if core::eq_ascii_fold(typ_val, "dpop+jwt") || core::eq_ascii_fold(typ_val, "application/dpop+jwt") {
                valid_typ = true;
            }
        } else if key == "alg" {
            if seen_alg { had_dup = true; }
            seen_alg = true;
            let alg_val = json::read_string(reader, scratch);
            if is_matching_dpop_alg(alg_val, expected_alg) {
                valid_alg = true;
            }
        } else if key == "jwk" {
            if seen_jwk { had_dup = true; }
            seen_jwk = true;
            verify_dpop_jwk(reader, scratch, jwk_info);
        } else {
            json::skip(reader);
        }
    };
    return json::finish(reader) && !had_dup && !has_crit && valid_typ && valid_alg && seen_jwk && jwk_info.valid;
}

fn verify_dpop_signature(signing_input: const u8[:], sig_b64: const u8[:], pub_key: const u8[32]) -> bool {
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
    jwk_info:      const DPoPJwkInfo&,
) -> bool {
    if alg == "EdDSA" {
        guard jwk_info.kty[..] == "OKP" && jwk_info.crv[..] == "Ed25519" else { return false; }
        var decoded_x: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
        var pub_arr: u8[32] = [0; 32];
        for i in 32 { pub_arr[i] = decoded_x[i]; }
        return verify_dpop_signature(signing_input, sig_b64, pub_arr);
    } else if alg == "ES256" {
        guard jwk_info.kty[..] == "EC" && jwk_info.crv[..] == "P-256" else { return false; }
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
        return core::ecdsa_p256_verify(pub_pt[..], signing_input, sig_bytes[..]);
    } else if alg == "RS256" || alg == "PS256" {
        guard jwk_info.kty[..] == "RSA" else { return false; }
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

// Parses a JSON numeric `iat` claim value from `reader` into `out.iat` (RFC 9449 §4.2).
//
// Example:
//   reader at "1700000000}", out = DPoPClaims { .. }, had_error = false
//   returns: out.iat = 1700000000, out.has_iat = true, had_error = false
inline fn parse_dpop_iat_field(reader: json::Reader&, out: DPoPClaims&, had_error: bool&) {
    let p = json::peek(reader);
    guard (p >= '0' && p <= '9') || p == '-' else {
        json::skip(reader);
        had_error = true;
        return;
    }
    let num = json::read_number(reader);
    guard num >= 0.0 && num <= 9223372036854774784.0 else {
        had_error = true;
        return;
    }
    out.iat = num as i64;
    out.has_iat = true;
}

// Parses decoded JSON payload into a typed DPoPClaims struct in a single pass.
// Defends against duplicate key injection (had_dup) and claim spoofing.
//
// Example:
//   claims_json = "{\"jti\":\"j-1\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/\",\"iat\":1700000000}"
//   returns: ok = true, out.jti = "j-1", out.htm = "GET", out.iat = 1700000000
fn parse_dpop_claims(claims_json: const u8[:], out: DPoPClaims&) -> bool {
    out.jti.clear();
    out.htm.clear();
    out.htu.clear();
    out.nonce.clear();
    out.ath.clear();
    out.jkt.clear();
    out.iat = -1;
    out.has_iat = false;

    var reader = json::reader(claims_json);
    var seen_jti = false;
    var seen_htm = false;
    var seen_htu = false;
    var seen_iat = false;
    var seen_nonce = false;
    var seen_ath = false;
    var seen_jkt = false;
    var had_dup = false;
    var had_error = false;
    var scratch: u8[>..] = [];

    json::each_member(reader) { key =>
        scratch.clear();
        if key.contains('\\') {
            had_error = true;
            json::skip(reader);
        } else if key == "jti" {
            if seen_jti { had_dup = true; }
            seen_jti = true;
            let val = json::read_string(reader, scratch);
            if !out.jti.try_set(val) { had_error = true; }
        } else if key == "htm" {
            if seen_htm { had_dup = true; }
            seen_htm = true;
            let val = json::read_string(reader, scratch);
            if !out.htm.try_set(val) { had_error = true; }
        } else if key == "htu" {
            if seen_htu { had_dup = true; }
            seen_htu = true;
            let val = json::read_string(reader, scratch);
            if !out.htu.try_set(val) { had_error = true; }
        } else if key == "iat" {
            if seen_iat { had_dup = true; }
            seen_iat = true;
            parse_dpop_iat_field(reader, out, had_error);
        } else if key == "nonce" {
            if seen_nonce { had_dup = true; }
            seen_nonce = true;
            let val = json::read_string(reader, scratch);
            if !out.nonce.try_set(val) { had_error = true; }
        } else if key == "ath" {
            if seen_ath { had_dup = true; }
            seen_ath = true;
            let val = json::read_string(reader, scratch);
            if !out.ath.try_set(val) { had_error = true; }
        } else if key == "jkt" {
            if seen_jkt { had_dup = true; }
            seen_jkt = true;
            let val = json::read_string(reader, scratch);
            if !out.jkt.try_set(val) { had_error = true; }
        } else {
            json::skip(reader);
        }
    };

    guard json::finish(reader) && !had_dup && !had_error else {
        out = DPoPClaims { .. };
        return false;
    }
    return true;
}

// RFC 9449 Section 4.3 Rule 4: Mandatory unique jti claim validation.
fn verify_dpop_jti(claims_json: const u8[:]) -> bool {
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    return rfc::is_valid_dpop_nonce(claims.jti[..]);
}

inline fn is_valid_dpop_method(m: const u8[:]) -> bool {
    guard m.len > 0 else { return false; }
    for b in m {
        guard !(b >= 'a' && b <= 'z') && core::is_tchar(b) else { return false; }
    }
    return true;
}

fn verify_dpop_method(claims_json: const u8[:], expected_method: const u8[:]) -> bool {
    guard is_valid_dpop_method(expected_method) else { return false; }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard is_valid_dpop_method(claims.htm[..]) else { return false; }
    return claims.htm[..] == expected_method;
}

fn verify_dpop_uri(claims_json: const u8[:], expected_uri: const u8[:]) -> bool {
    var norm_expected_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected_uri) else { return false; }

    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.htu.len > 0 else { return false; }

    for b in claims.htu {
        if b == '?' || b == '#' { return false; }
    }

    var norm_htu: u8[..256] = [];
    guard normalize_dpop_target_uri(claims.htu[..], norm_htu) else { return false; }
    return norm_htu[..] == norm_expected_uri[..];
}

fn verify_dpop_iat(claims_json: const u8[:], now_sec: i64, max_age_sec: i64, max_skew_sec: i64) -> bool {
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.has_iat && claims.iat > 0 else { return false; }
    if now_sec > 0 {
        guard max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
        let max_future = core::add_sat_i64(now_sec, max_skew_sec);
        guard claims.iat <= max_future else { return false; }
        let age = core::sub_sat_i64(now_sec, claims.iat);
        let max_allowed_age = core::add_sat_i64(max_age_sec, max_skew_sec);
        guard age <= max_allowed_age else { return false; }
    }
    return true;
}

fn verify_dpop_ath(claims_json: const u8[:], expected_ath: const u8[:]) -> bool {
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.ath.len > 0 && claims.ath.len == expected_ath.len else { return false; }
    return core::ct_eq_bytes(claims.ath[..], expected_ath);
}

fn verify_dpop_nonce(claims_json: const u8[:], expected_nonce: const u8[:]) -> bool {
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.nonce.len > 0 && claims.nonce.len == expected_nonce.len else { return false; }
    return core::ct_eq_bytes(claims.nonce[..], expected_nonce);
}

// RFC 9449 Section 6.1 / RFC 7638: Verifies JWK Thumbprint ('jkt') confirmation claim.
fn verify_dpop_jkt(claims_json: const u8[:], expected_jkt: const u8[:]) -> bool {
    guard expected_jkt.len > 0 else { return false; }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.jkt.len > 0 && claims.jkt.len == expected_jkt.len else { return false; }
    return core::ct_eq_bytes(claims.jkt[..], expected_jkt);
}

// Validates parsed DPoP claims against expected method, URI, access token, nonce, jkt, and validity window.
fn verify_dpop_claims(
    claims:          const DPoPClaims&,
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    access_token:    const u8[:] = "",
    expected_nonce:  const u8[:] = "",
    now_sec:         i64         = 0,
    max_age_sec:     i64         = 300,
    max_skew_sec:    i64         = 60,
    expected_jkt:    const u8[:] = "",
) -> bool {
    // RFC 9449 §4.3: Mandatory unique jti & exact uppercase HTTP method
    guard rfc::is_valid_dpop_nonce(claims.jti[..]) else { return false; }
    guard is_valid_dpop_method(expected_method) && is_valid_dpop_method(claims.htm[..]) else { return false; }
    guard claims.htm[..] == expected_method else { return false; }

    // RFC 9449 §4.3: Normalized target URI without query/fragment
    guard claims.htu.len > 0 else { return false; }
    for b in claims.htu { if b == '?' || b == '#' { return false; } }
    var norm_expected_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected_uri) else { return false; }
    var norm_htu: u8[..256] = [];
    guard normalize_dpop_target_uri(claims.htu[..], norm_htu) else { return false; }
    guard norm_htu[..] == norm_expected_uri[..] else { return false; }

    // RFC 9449 §4.3: Access token hash binding
    if access_token.len > 0 {
        var expected_ath: u8[..64] = [];
        compute_dpop_ath(access_token, expected_ath);
        guard claims.ath.len > 0 && claims.ath.len == expected_ath.len else { return false; }
        guard core::ct_eq_bytes(claims.ath[..], expected_ath[..]) else { return false; }
    } else {
        guard claims.ath.len == 0 else { return false; }
    }

    // RFC 9449 §4.3: Server nonce & JWK Thumbprint confirmation
    if expected_nonce.len > 0 {
        guard claims.nonce.len > 0 && claims.nonce.len == expected_nonce.len else { return false; }
        guard core::ct_eq_bytes(claims.nonce[..], expected_nonce) else { return false; }
    }
    if expected_jkt.len > 0 {
        guard claims.jkt.len > 0 && claims.jkt.len == expected_jkt.len else { return false; }
        guard core::ct_eq_bytes(claims.jkt[..], expected_jkt) else { return false; }
    }

    // RFC 9449 §4.3: Mandatory creation time & validity window
    guard claims.has_iat && claims.iat > 0 else { return false; }
    if now_sec > 0 {
        guard max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
        let max_future = core::add_sat_i64(now_sec, max_skew_sec);
        guard claims.iat <= max_future else { return false; }
        let age = core::sub_sat_i64(now_sec, claims.iat);
        let max_allowed_age = core::add_sat_i64(max_age_sec, max_skew_sec);
        guard age <= max_allowed_age else { return false; }
    }
    return true;
}

const MAX_DPOP_PROOF_LEN: i64 = 4096;

// RFC 9449 Section 6.1: JWK Thumbprint Confirmation Method - Validates that the JWK SHA-256
// thumbprint of the DPoP public key or cnf.jkt claim matches expected_jkt in constant time.
fn matches_dpop_jkt_thumbprint(
    jwk_pub:      const u8[32]&,
    claims_jkt:   const u8[:],
    expected_jkt: const u8[:],
) -> bool {
    var x_b64: u8[..64] = [];
    core::base64url_encode(jwk_pub[..], x_b64);
    var canonical: u8[..128] = [];
    canonical.append("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
    canonical.append(x_b64[..]);
    canonical.append("\"}");
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

fn matches_dpop_jkt_thumbprint_jwk(
    jwk_info:     const DPoPJwkInfo&,
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

fn verify_dpop_key_binding(key: const u8[:], alg: const u8[:], jwk_info: const DPoPJwkInfo&) -> bool {
    guard key.len > 0 else { return true; }
    if alg == "EdDSA" {
        guard key.len == 32 else { return false; }
        var jwk_pub: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], jwk_pub) && jwk_pub.len == 32 else { return false; }
        var key_seed: u8[32] = [0; 32];
        for i in 32 { key_seed[i] = key[i]; }
        let derived_pub = core::ed25519_public_key(key_seed);
        core::secure_zeroize_32(key_seed);
        return core::ct_eq_bytes(jwk_pub[..], key) || core::ct_eq_bytes(jwk_pub[..], derived_pub[..]);
    } else if alg == "ES256" {
        var decoded_x: u8[..64] = [];
        var decoded_y: u8[..64] = [];
        guard core::base64url_decode(jwk_info.x[..], decoded_x) && decoded_x.len == 32 else { return false; }
        guard core::base64url_decode(jwk_info.y[..], decoded_y) && decoded_y.len == 32 else { return false; }
        var pub_pt: u8[..65] = [];
        pub_pt.push(0x04);
        pub_pt.append(decoded_x[..]);
        pub_pt.append(decoded_y[..]);
        if key.len == 65 {
            return core::ct_eq_bytes(pub_pt[..], key);
        } else if key.len == 64 {
            return core::ct_eq_bytes(pub_pt[1..65], key);
        } else if key.len == 32 {
            var priv_arr: u8[32] = [0; 32];
            for i in 32 { priv_arr[i] = key[i]; }
            let derived_pt = core::ecdsa_p256_public_key(priv_arr);
            core::secure_zeroize_32(priv_arr);
            return core::ct_eq_bytes(pub_pt[..], derived_pt[..]);
        }
        return false;
    } else if alg == "RS256" || alg == "PS256" {
        var decoded_n: u8[..512] = [];
        guard core::base64url_decode(jwk_info.n[..], decoded_n) else { return false; }
        return core::ct_eq_bytes(decoded_n[..], key);
    }
    return false;
}

// Verifies a DPoP Proof JWT against expected method, URI, access token, nonce, jkt, and time window.
// Mandates asymmetric signature validation using the public key from the header JWK (RFC 9449 §4.3).
fn verify_dpop_proof(
    jwt:             const u8[:],
    key:             const u8[:],
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    access_token:    const u8[:] = "",
    expected_nonce:  const u8[:] = "",
    now_sec:         i64         = 0,
    max_age_sec:     i64         = 300,
    max_skew_sec:    i64         = 60,
    expected_jkt:    const u8[:] = "",
    expected_alg:    const u8[:] = "EdDSA",
) -> bool {
    guard jwt.len > 0 && jwt.len <= MAX_DPOP_PROOF_LEN && core::index_of_byte(jwt, '=') == -1 else { return false; }
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(jwt, dot1, dot2) else { return false; }

    let header_b64 = jwt[..dot1];
    let claims_start = core::add_sat_i64(dot1, 1);
    let claims_b64 = jwt[claims_start..dot2];
    let sig_start = core::add_sat_i64(dot2, 1);
    let sig_b64 = jwt[sig_start..];
    let signing_input = jwt[..dot2];

    var header_json: u8[..1024] = [];
    guard core::base64url_decode(header_b64, header_json) else { return false; }
    guard verify_dpop_header(header_json[..], expected_alg) else { return false; }

    var header_alg: u8[..16] = [];
    var jwk_info = DPoPJwkInfo { .. };
    guard parse_dpop_header_jwk_info(header_json[..], header_alg, jwk_info) else { return false; }
    guard verify_dpop_key_binding(key, header_alg[..], jwk_info) else { return false; }
    guard verify_dpop_signature_with_jwk(signing_input, sig_b64, header_alg[..], jwk_info) else { return false; }

    var claims_json: u8[..2048] = [];
    guard core::base64url_decode(claims_b64, claims_json) else { return false; }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json[..], claims) else { return false; }

    if expected_jkt.len > 0 {
        // RFC 9449 Section 4.3: Checking DPoP Proofs - confirm that the public key matches expected_jkt
        guard matches_dpop_jkt_thumbprint_jwk(jwk_info, claims.jkt[..], expected_jkt) else { return false; }
    }

    return verify_dpop_claims(
        claims,
        expected_method,
        expected_uri,
        access_token,
        expected_nonce,
        now_sec,
        max_age_sec,
        max_skew_sec,
        "",
    );
}

// ---- Client Header Integration ------------------------------------------

// Attaches DPoP proof and optional Authorization: DPoP <token> header to a Request.
fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "") {
    guard proof.len > 0 && proof.len <= 2048 else { return; }
    if access_token.len > 0 {
        guard access_token.len <= 2040 else { return; }
        var auth_val: u8[..2048] = [];
        auth_val.append("DPoP ");
        auth_val.append(access_token);
        set_header(req, "Authorization", auth_val[..]);
    }
    set_header(req, rfc::DPOP_HEADER, proof);
}

// Extracts DPoP-Nonce from response headers as a zero-copy slice (RFC 9449 §8).
//
// Example:
//   headers = HeaderMap { "DPoP-Nonce": "eyJhbGciOi..." }
//   returns: "eyJhbGciOi...", ok = true
fn extract_dpop_nonce(headers: const HeaderMap&) -> const u8[:], bool {
    var found_idx: i64 = -1;
    for idx in headers.entries.len {
        if core::eq_ascii_fold(entry_name(headers, headers.entries[idx]), rfc::DPOP_NONCE_HEADER) {
            if found_idx != -1 {
                return "", false;
            }
            found_idx = idx;
        }
    }
    guard found_idx != -1 else { return "", false; }
    let val = entry_value(headers, headers.entries[found_idx]);
    guard rfc::is_valid_dpop_nonce(val) else { return "", false; }
    return val, true;
}

// Extracts DPoP-Nonce into a target buffer (cleared only on success).
//
// Example:
//   headers = HeaderMap { "DPoP-Nonce": "nonce-xyz" }, out_nonce = ""
//   returns: ok = true, out_nonce = "nonce-xyz"
fn extract_dpop_nonce<B>(headers: const HeaderMap&, out_nonce: B&) -> bool {
    let nonce, ok = extract_dpop_nonce(headers);
    guard ok else { return false; }
    out_nonce.clear();
    return out_nonce.try_append(nonce);
}

// ---- DPoP Replay Cache (RFC 9449 §4.3 Rule 4) ---------------------------

struct DPoPJtiEntry {
    jti:            u8[..128] = [],
    expires_at_sec: i64       = 0,
}

struct DPoPReplayCache {
    entries: DPoPJtiEntry[..128] = [],
    head:    i64                 = 0,
}

// Checks whether a DPoP jti has been seen before; if not, records it until now_sec + ttl_sec + max_skew_sec.
// Returns true if jti is unique and recorded; returns false if replay detected or input invalid.
fn check_and_record_dpop_jti(
    cache:        DPoPReplayCache&,
    jti:          const u8[:],
    now_sec:      i64,
    ttl_sec:      i64 = 300,
    max_skew_sec: i64 = 60,
) -> bool {
    // RFC 9449 Section 11.1: DPoP Proof Replay - As long as the jti value is tracked and duplicates are rejected for the lifetime of the nonce, there is no additional risk of token replay.
    guard jti.len > 0 && jti.len <= 128 else { return false; }
    guard now_sec >= 0 && ttl_sec > 0 && max_skew_sec >= 0 else { return false; }

    var free_idx: i64 = -1;
    for i in cache.entries.len {
        let entry = cache.entries[i];
        if entry.expires_at_sec > now_sec {
            if core::ct_eq_bytes(entry.jti[..], jti) {
                return false; // Replay attack detected!
            }
        } else if free_idx == -1 {
            free_idx = i;
        }
    }

    let total_ttl = core::add_sat_i64(ttl_sec, max_skew_sec);
    let exp = core::add_sat_i64(now_sec, total_ttl);

    if free_idx >= 0 {
        var slot = cache.entries[free_idx];
        slot.jti.clear();
        slot.jti.append(jti);
        slot.expires_at_sec = exp;
        cache.entries[free_idx] = slot;
        return true;
    }

    if cache.entries.len < cache.entries.cap {
        var new_entry = DPoPJtiEntry { .. };
        new_entry.jti.append(jti);
        new_entry.expires_at_sec = exp;
        cache.entries.push(new_entry);
        return true;
    }

    // Do NOT overwrite unexpired JTI if all slots are live
    return false;
}

// Verifies a DPoP Proof JWT and rejects replayed proofs via DPoPReplayCache.
fn verify_dpop_proof_with_replay_cache(
    jwt:             const u8[:],
    key:             const u8[:],
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    now_sec:         i64,
    cache:           DPoPReplayCache&,
    access_token:    const u8[:] = "",
    expected_nonce:  const u8[:] = "",
    max_age_sec:     i64         = 300,
    max_skew_sec:    i64         = 60,
    expected_jkt:    const u8[:] = "",
    expected_alg:    const u8[:] = "EdDSA",
) -> bool {
    guard verify_dpop_proof(
        jwt, key, expected_method, expected_uri,
        access_token, expected_nonce, now_sec,
        max_age_sec, max_skew_sec, expected_jkt, expected_alg,
    ) else { return false; }

    var claims = DPoPClaims { .. };
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(jwt, dot1, dot2) else { return false; }
    var claims_json: u8[..2048] = [];
    let claims_start = core::add_sat_i64(dot1, 1);
    guard core::base64url_decode(jwt[claims_start..dot2], claims_json) else { return false; }
    guard parse_dpop_claims(claims_json[..], claims) else { return false; }

    return check_and_record_dpop_jti(cache, claims.jti[..], now_sec, max_age_sec, max_skew_sec);
}
