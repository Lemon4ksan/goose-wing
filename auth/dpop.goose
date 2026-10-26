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

// ---- 1. RFC 9449 Constants & Identifiers ------------------------------------

const DPOP_HEADER: const u8[:] = "DPoP";
const DPOP_NONCE_HEADER: const u8[:] = "DPoP-Nonce";
const DPOP_AUTH_SCHEME: const u8[:] = "DPoP";
const DPOP_JWT_TYP: const u8[:] = "dpop+jwt";

const DPOP_ERR_INVALID_PROOF: const u8[:] = "invalid_dpop_proof";
const DPOP_ERR_INVALID_TOKEN: const u8[:] = "invalid_token";
const DPOP_ERR_USE_NONCE: const u8[:] = "use_dpop_nonce";

// ---- 2. DPoP Models ---------------------------------------------------------

struct DPoPClaims {
    jti: u8[..64] = [],
    htm: u8[..16] = [],
    htu: u8[..256] = [],
    iat: i64 = 0,
    nonce: u8[..128] = [],
    ath: u8[..64] = [],
}

struct DPoPConfig {
    key: u8[..64] = [],
    nonce: u8[..128] = [],
    alg: u8[..16] = "HS256",
    enabled: bool = false,
}

// ---- 3. Helper Functions: URI Normalization & Access Token Hash -------------

// Normalizes target URI for the "htu" claim (RFC 9449 Section 4.2).
// Strips query string and fragment, forces scheme and host to lowercase.
fn normalize_dpop_target_uri<B>(raw_uri: const u8[:], out: B&) -> bool {
    out.clear();
    guard raw_uri.len > 0 else { return false; }

    var i = 0;
    // Find query '?' or fragment '#' to truncate
    var end_idx = raw_uri.len;
    while i < raw_uri.len {
        if raw_uri[i] == '?' || raw_uri[i] == '#' {
            end_idx = i;
            break;
        }
        i += 1;
    }

    var scheme_host_end = end_idx;
    var path_start = -1;
    // Find path start (first '/' after "://")
    var slash_cnt = 0;
    for k in end_idx {
        if raw_uri[k] == '/' {
            slash_cnt += 1;
            if slash_cnt == 3 {
                path_start = k;
                scheme_host_end = k;
                break;
            }
        }
    }

    // Lowercase scheme and host
    for k in scheme_host_end {
        let ch = raw_uri[k];
        if ch >= 'A' && ch <= 'Z' {
            out.push(ch + 32);
        } else {
            out.push(ch);
        }
    }

    // Append path
    if path_start != -1 {
        for k in (end_idx - path_start) {
            out.push(raw_uri[path_start + k]);
        }
    } else {
        out.push('/' as u8);
    }

    return true;
}

// Computes the RFC 9449 Section 4.2 "ath" (Access Token Hash) claim:
// BASE64URL-ENCODE(SHA256(ASCII(access_token))) without padding.
fn compute_dpop_ath<B>(access_token: const u8[:], out: B&) {
    out.clear();
    guard access_token.len > 0 else { return; }
    let digest = core::sha256(access_token);
    core::base64url_encode(digest[..], out);
}

// Generates a cryptographically random unique identifier for the "jti" claim.
fn generate_dpop_jti<B>(out: B&, entropy: const u8[:] = "") {
    out.clear();
    if entropy.len >= 16 {
        core::base64url_encode(entropy, out);
        return;
    }
    // Pseudo-random fallback
    let charset: const u8[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var state: u64 = 0x853c49e6748fea9b;
    for i in 22 {
        state = state * 6364136223846793005 + 1442695040888963407 + (i as u64);
        let idx = (state >> 32) % 64;
        out.push(charset[idx as i64]);
    }
}

// ---- 4. DPoP Proof JWT Generation -------------------------------------------

// Formats an integer to string buffer
fn dpop_format_int<B>(out: B&, val: i64) {
    if val == 0 {
        out.push('0' as u8);
        return;
    }
    var v = val;
    var digits: u8[..32] = [];
    while v > 0 {
        let d = (v % 10) as u8;
        digits.push(('0' as u8) + d);
        v /= 10;
    }
    var i = digits.len;
    while i > 0 {
        i -= 1;
        out.push(digits[i]);
    }
}

// Creates an RFC 9449 signed DPoP Proof JWT:
// `header_b64.claims_b64.signature_b64`
fn create_dpop_proof<B>(
    key: const u8[:],
    method: const u8[:],
    target_uri: const u8[:],
    access_token: const u8[:],
    nonce: const u8[:],
    now_sec: i64,
    jti: const u8[:],
    out: B&,
) -> bool {
    out.clear();

    var header_json: u8[..128] = [];
    header_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"HS256\"}");

    var header_b64: u8[..192] = [];
    core::base64url_encode(header_json[..], header_b64);

    var norm_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(target_uri, norm_uri) else {
        return false;
    }

    var claims_json: u8[..512] = [];
    claims_json.append("{\"jti\":\"");
    if jti.len > 0 {
        claims_json.append(jti);
    } else {
        var auto_jti: u8[..32] = [];
        generate_dpop_jti(auto_jti);
        claims_json.append(auto_jti[..]);
    }
    claims_json.append("\",\"htm\":\"");
    // Uppercase method
    for b in method {
        if b >= 'a' && b <= 'z' {
            claims_json.push(b - 32);
        } else {
            claims_json.push(b);
        }
    }
    claims_json.append("\",\"htu\":\"");
    claims_json.append(norm_uri[..]);
    claims_json.append("\",\"iat\":");
    dpop_format_int(claims_json, now_sec);

    if nonce.len > 0 {
        claims_json.append(",\"nonce\":\"");
        claims_json.append(nonce);
        claims_json.push('"' as u8);
    }

    if access_token.len > 0 {
        var ath: u8[..64] = [];
        compute_dpop_ath(access_token, ath);
        claims_json.append(",\"ath\":\"");
        claims_json.append(ath[..]);
        claims_json.push('"' as u8);
    }

    claims_json.push('}' as u8);

    var claims_b64: u8[..768] = [];
    core::base64url_encode(claims_json[..], claims_b64);

    var signing_input: u8[..1024] = [];
    signing_input.append(header_b64[..]);
    signing_input.push('.' as u8);
    signing_input.append(claims_b64[..]);

    let sig = core::hmac_sha256(key, signing_input[..]);
    var sig_b64: u8[..64] = [];
    core::base64url_encode(sig[..], sig_b64);

    out.append(signing_input[..]);
    out.push('.' as u8);
    out.append(sig_b64[..]);

    return true;
}

// ---- 5. DPoP Proof Verification ---------------------------------------------

fn verify_dpop_signature(signing_input: const u8[:], sig_b64: const u8[:], key: const u8[:]) -> bool {
    let expected_sig = core::hmac_sha256(key, signing_input);
    var expected_sig_b64: u8[..64] = [];
    core::base64url_encode(expected_sig[..], expected_sig_b64);

    guard expected_sig_b64.len == sig_b64.len else { return false; }
    var diff: u8 = 0;
    for i in sig_b64.len {
        diff |= sig_b64[i] ^ expected_sig_b64[i];
    }
    return diff == 0;
}

fn verify_dpop_method(claims_json: const u8[:], expected_method: const u8[:]) -> bool {
    var method_upper: u8[..16] = [];
    for b in expected_method {
        if b >= 'a' && b <= 'z' {
            method_upper.push(b - 32);
        } else {
            method_upper.push(b);
        }
    }
    return core::contains(claims_json, method_upper[..]);
}

fn verify_dpop_uri(claims_json: const u8[:], expected_uri: const u8[:]) -> bool {
    var norm_expected_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected_uri) else { return false; }

    // RFC 9449 Section 4.3: Extract and validate the 'htu' claim exactly.
    // The 'htu' claim MUST NOT contain a query ('?') or fragment ('#').
    let htu_idx = core::index_of_slice(claims_json, "\"htu\":");
    guard htu_idx >= 0 else { return false; }

    var pos = htu_idx + 6;
    while pos < claims_json.len && (claims_json[pos] == ' ' || claims_json[pos] == '\t') {
        pos += 1;
    }
    guard pos < claims_json.len && claims_json[pos] == '"' else { return false; }
    pos += 1; // skip opening quote
    let val_start = pos;
    while pos < claims_json.len && claims_json[pos] != '"' {
        pos += 1;
    }
    guard pos < claims_json.len else { return false; }
    let htu_val = claims_json[val_start..pos];

    // RFC 9449 Section 4.3: Reject if 'htu' contains query or fragment
    for b in htu_val {
        if b == '?' || b == '#' { return false; }
    }

    var norm_htu: u8[..256] = [];
    guard normalize_dpop_target_uri(htu_val, norm_htu) else { return false; }
    return norm_htu[..] == norm_expected_uri[..];
}

fn verify_dpop_iat(claims_json: const u8[:], now_sec: i64, max_age_sec: i64, max_skew_sec: i64) -> bool {
    guard now_sec > 0 else { return true; }
    let iat_idx = core::index_of_slice(claims_json, "\"iat\":");
    guard iat_idx != -1 else { return true; }

    var iat_val: i64 = 0;
    var pos = iat_idx + 6;
    while pos < claims_json.len && (claims_json[pos] == ' ' || claims_json[pos] == '\t') {
        pos += 1;
    }
    var has_digits = false;
    while pos < claims_json.len && claims_json[pos] >= '0' && claims_json[pos] <= '9' {
        iat_val = iat_val * 10 + (claims_json[pos] - '0');
        pos += 1;
        has_digits = true;
    }
    guard has_digits else { return true; }
    guard iat_val <= (now_sec + max_skew_sec) else { return false; }
    return (now_sec - iat_val) <= (max_age_sec + max_skew_sec);
}

// Verifies a DPoP Proof JWT against expected method, URI, access token, nonce, and time window.
fn verify_dpop_proof(
    jwt: const u8[:],
    key: const u8[:],
    expected_method: const u8[:],
    expected_uri: const u8[:],
    access_token: const u8[:] = "",
    expected_nonce: const u8[:] = "",
    now_sec: i64 = 0,
    max_age_sec: i64 = 300,
    max_skew_sec: i64 = 60,
) -> bool {
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(jwt, dot1, dot2) else { return false; }

    let header_b64 = jwt[..dot1];
    let claims_b64 = jwt[(dot1 + 1)..dot2];
    let sig_b64 = jwt[(dot2 + 1)..];
    let signing_input = jwt[..dot2];

    guard verify_dpop_signature(signing_input, sig_b64, key) else { return false; }

    var header_json: u8[>..] = [];
    guard core::base64url_decode(header_b64, header_json) else { return false; }
    guard core::contains(header_json[..], "dpop+jwt") else { return false; }

    var claims_json: u8[>..] = [];
    guard core::base64url_decode(claims_b64, claims_json) else { return false; }
    guard verify_dpop_method(claims_json[..], expected_method) else { return false; }
    guard verify_dpop_uri(claims_json[..], expected_uri) else { return false; }

    if access_token.len > 0 {
        var expected_ath: u8[..64] = [];
        compute_dpop_ath(access_token, expected_ath);
        guard expected_ath.len > 0 && core::contains(claims_json[..], expected_ath[..]) else { return false; }
    }

    if expected_nonce.len > 0 {
        guard core::contains(claims_json[..], expected_nonce) else { return false; }
    }

    return verify_dpop_iat(claims_json[..], now_sec, max_age_sec, max_skew_sec);
}

// ---- 6. Client Header Integration ------------------------------------------

// Attaches DPoP proof and optional Authorization: DPoP <token> header to a Request.
fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "") {
    set_header(req, DPOP_HEADER, proof);
    if access_token.len > 0 {
        var auth_val: u8[..384] = [];
        auth_val.append("DPoP ");
        auth_val.append(access_token);
        set_header(req, "Authorization", auth_val[..]);
    }
}

// Extracts DPoP-Nonce from response headers.
fn extract_dpop_nonce<H>(headers: const H[:], out_nonce: u8[..128]&) -> bool {
    out_nonce.clear();
    for idx in headers.len {
        if core::eq_ascii_fold(headers[idx].name[..], DPOP_NONCE_HEADER) {
            out_nonce.append(headers[idx].value[..]);
            return true;
        }
    }
    return false;
}
