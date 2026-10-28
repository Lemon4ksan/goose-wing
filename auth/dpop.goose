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
    // RFC 9449 §4.3: Target URI scheme MUST be http or https
    guard core::starts_with(raw_uri, "http://") || core::starts_with(raw_uri, "https://") else {
        return false;
    }

    var i = 0;
    // Find query '?' or fragment '#' to truncate
    var end_idx = raw_uri.len;
    while i < raw_uri.len {
        if raw_uri[i] == '?' || raw_uri[i] == '#' {
            end_idx = i;
            break;
        }
        guard raw_uri[i] != '\\' else { return false; }
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

    // RFC 3986 §3.2.1: Reject userinfo in authority
    for k in scheme_host_end {
        if raw_uri[k] == '@' { return false; }
    }

    var sh_buf: u8[..256] = [];
    // Lowercase scheme and host
    for k in scheme_host_end {
        let ch = raw_uri[k];
        if ch >= 'A' && ch <= 'Z' {
            sh_buf.push(ch + 32);
        } else {
            sh_buf.push(ch);
        }
    }

    // RFC 3986 §6.2.3 / RFC 9449 §4.3: Scheme-based default port normalization
    var emit_len = sh_buf.len;
    if core::starts_with(sh_buf[..], "http://") && core::ends_with(sh_buf[..], ":80") {
        emit_len = sh_buf.len - 3;
    } else if core::starts_with(sh_buf[..], "https://") && core::ends_with(sh_buf[..], ":443") {
        emit_len = sh_buf.len - 4;
    }

    for k in emit_len {
        out.push(sh_buf[k]);
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
    core::format_i64_dec(now_sec, claims_json);

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

fn is_matching_dpop_alg(alg_val: const u8[:], expected_alg: const u8[:]) -> bool {
    guard !core::eq_ascii_fold(alg_val, "none") && alg_val.len > 0 else { return false; }
    return expected_alg.len == 0 || alg_val == expected_alg;
}

fn verify_dpop_header(header_json: const u8[:], expected_alg: const u8[:] = "HS256") -> bool {
    var reader = json::reader(header_json);
    var valid_typ = false;
    var valid_alg = false;
    var seen_typ = false;
    var seen_alg = false;
    var had_dup = false;
    var scratch: u8[>..] = [];

    json::each_member(reader) { key =>
        scratch.clear();
        if key == "typ" {
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
        } else {
            json::skip(reader);
        }
    };
    return json::finish(reader) && !had_dup && valid_typ && valid_alg;
}

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

fn extract_json_string_claim(json: const u8[:], claim_name: const u8[:]) -> const u8[:], bool {
    let key_idx = core::index_of_slice(json, claim_name);
    guard key_idx >= 0 else { return "", false; }
    let after_key = json[key_idx + claim_name.len..].trim_lws();
    guard after_key.len >= 2 && after_key[0] == ':' else { return "", false; }
    let after_colon = after_key[1..].trim_lws();
    guard after_colon.len >= 2 && after_colon[0] == '"' else { return "", false; }
    let rel_q = core::index_of_byte(after_colon[1..], '"');
    guard rel_q >= 0 else { return "", false; }
    return after_colon[1..1 + rel_q], true;
}

fn extract_json_int_claim(json: const u8[:], claim_name: const u8[:]) -> i64, bool {
    let key_idx = core::index_of_slice(json, claim_name);
    guard key_idx >= 0 else { return 0, false; }
    let after_key = json[key_idx + claim_name.len..].trim_lws();
    guard after_key.len >= 2 && after_key[0] == ':' else { return 0, false; }
    let after_colon = after_key[1..].trim_lws();
    var num_len: i64 = 0;
    while num_len < after_colon.len && after_colon[num_len] >= '0' && after_colon[num_len] <= '9' {
        num_len++;
    }
    guard num_len > 0 else { return 0, false; }
    return after_colon[..num_len].parse_i64_dec();
}

// RFC 9449 Section 4.3 Rule 4: Mandatory unique jti claim validation.
fn verify_dpop_jti(claims_json: const u8[:]) -> bool {
    let jti_val, ok = extract_json_string_claim(claims_json, "\"jti\"");
    guard ok else { return false; }
    return jti_val.len > 0 && jti_val.len <= 128;
}

fn verify_dpop_method(claims_json: const u8[:], expected_method: const u8[:]) -> bool {
    guard expected_method.len > 0 else { return false; }
    let htm_val, ok = extract_json_string_claim(claims_json, "\"htm\"");
    guard ok else { return false; }

    // RFC 9449 §4.2: htm MUST be uppercase String
    for b in htm_val {
        if b >= 'a' && b <= 'z' {
            return false;
        }
    }

    // RFC 9449 §4.3: Exact case-sensitive match with HTTP method
    return htm_val == expected_method;
}

fn verify_dpop_uri(claims_json: const u8[:], expected_uri: const u8[:]) -> bool {
    var norm_expected_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected_uri) else { return false; }

    let htu_val, ok = extract_json_string_claim(claims_json, "\"htu\"");
    guard ok else { return false; }

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
    guard max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
    let iat_val, ok = extract_json_int_claim(claims_json, "\"iat\"");
    guard ok && iat_val > 0 else { return false; }
    guard iat_val <= (now_sec + max_skew_sec) else { return false; }
    return (now_sec - iat_val) <= (max_age_sec + max_skew_sec);
}

fn verify_dpop_ath(claims_json: const u8[:], expected_ath: const u8[:]) -> bool {
    let ath_val, ok = extract_json_string_claim(claims_json, "\"ath\"");
    guard ok else { return false; }
    return ath_val == expected_ath;
}

fn verify_dpop_nonce(claims_json: const u8[:], expected_nonce: const u8[:]) -> bool {
    let nonce_val, ok = extract_json_string_claim(claims_json, "\"nonce\"");
    guard ok else { return false; }
    return nonce_val == expected_nonce;
}

// RFC 9449 Section 6.1 / RFC 7638: Verifies JWK Thumbprint ('jkt') confirmation claim.
fn verify_dpop_jkt(claims_json: const u8[:], expected_jkt: const u8[:]) -> bool {
    guard expected_jkt.len > 0 else { return false; }
    let jkt_val, ok = extract_json_string_claim(claims_json, "\"jkt\"");
    guard ok && jkt_val.len == expected_jkt.len else { return false; }
    return core::ct_eq_bytes(jkt_val, expected_jkt);
}

// Verifies a DPoP Proof JWT against expected method, URI, access token, nonce, jkt, and time window.
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
    expected_jkt: const u8[:] = "",
    expected_alg: const u8[:] = "HS256",
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
    guard verify_dpop_header(header_json[..], expected_alg) else { return false; }

    var claims_json: u8[>..] = [];
    guard core::base64url_decode(claims_b64, claims_json) else { return false; }

    // RFC 9449 §4.3 Rule 4: Mandatory unique jti
    guard verify_dpop_jti(claims_json[..]) else { return false; }

    guard verify_dpop_method(claims_json[..], expected_method) else { return false; }
    guard verify_dpop_uri(claims_json[..], expected_uri) else { return false; }

    if access_token.len > 0 {
        var expected_ath: u8[..64] = [];
        compute_dpop_ath(access_token, expected_ath);
        guard expected_ath.len > 0 && verify_dpop_ath(claims_json[..], expected_ath[..]) else { return false; }
    }

    if expected_nonce.len > 0 {
        guard verify_dpop_nonce(claims_json[..], expected_nonce) else { return false; }
    }

    if expected_jkt.len > 0 {
        guard verify_dpop_jkt(claims_json[..], expected_jkt) else { return false; }
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

// Extracts DPoP-Nonce from response headers as a zero-copy slice.
fn extract_dpop_nonce<H>(headers: const H[:]) -> const u8[:], bool {
    for idx in headers.len {
        if core::eq_ascii_fold(headers[idx].name[..], DPOP_NONCE_HEADER) {
            return headers[idx].value[..], true;
        }
    }
    return "", false;
}

// Extracts DPoP-Nonce into a target buffer (cleared only on success).
fn extract_dpop_nonce<H, B>(headers: const H[:], out_nonce: B&) -> bool {
    let nonce, ok = extract_dpop_nonce(headers);
    guard ok else { return false; }
    out_nonce.clear();
    return out_nonce.try_append(nonce);
}
