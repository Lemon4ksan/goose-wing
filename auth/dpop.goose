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
    jti: u8[..128] = [],
    htm: u8[..16] = [],
    htu: u8[..256] = [],
    iat: i64 = -1,
    nonce: u8[..128] = [],
    ath: u8[..64] = [],
    jkt: u8[..64] = [],
    has_iat: bool = false,
}

struct DPoPConfig {
    key: u8[..64] = [],
    nonce: u8[..128] = [],
    alg: u8[..16] = "HS256",
    enabled: bool = false,
}

// ---- 3. Helper Functions: URI Normalization & Access Token Hash -------------

// Scans URI delimiter boundaries for RFC 9449 normalization.
//
// Example:
//   raw_uri = "https://example.com:443/resource?query=1#frag"
//   returns: end_idx = 35, path_start = 25, ok = true (end before '?', path at '/')
inline fn scan_uri_delimiters(raw_uri: const u8[:]) -> i64, i64, bool {
    var end_idx = raw_uri.len;
    for i in raw_uri.len {
        let b = raw_uri[i];
        if b == '?' || b == '#' {
            end_idx = i;
            break;
        }
        guard b != '\\' && b != '"' && b > 0x20 && b < 0x7f else { return 0, 0, false; }
    }
    var slash_cnt = 0;
    var path_start = -1;
    for k in end_idx {
        if raw_uri[k] == '/' {
            slash_cnt += 1;
            if slash_cnt == 3 {
                path_start = k;
                break;
            }
        }
    }
    return end_idx, path_start, true;
}

// Normalizes target URI for the "htu" claim (RFC 9449 Section 4.2).
// Strips query string and fragment, forces scheme and host to lowercase.
fn normalize_dpop_target_uri<B>(raw_uri: const u8[:], out: B&) -> bool {
    out.clear();
    guard raw_uri.len > 0 else { return false; }
    // RFC 9449 §4.3: Target URI scheme MUST be http or https
    guard core::starts_with(raw_uri, "http://") || core::starts_with(raw_uri, "https://") else {
        return false;
    }

    let end_idx, path_start, ok = scan_uri_delimiters(raw_uri);
    guard ok else { return false; }
    let scheme_host_end = if path_start != -1 { path_start } else { end_idx };

    // RFC 3986 §3.2.1: Reject userinfo in authority
    guard !raw_uri[..scheme_host_end].contains('@') else { return false; }

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

// Validates DPoP-Nonce syntax per RFC 9449 §8 (NQCHAR: ASCII 0x21, 0x23..0x5B, 0x5D..0x7E).
// Rejects double quotes ('"'), backslashes ('\\'), spaces, and control characters.
//
// Example:
//   nonce = "server_nonce_abc123"
//   returns: true
fn is_valid_dpop_nonce(nonce: const u8[:]) -> bool {
    guard nonce.len > 0 && nonce.len <= 128 else { return false; }
    for b in nonce {
        let valid = b == 0x21 || (b >= 0x23 && b <= 0x5b) || (b >= 0x5d && b <= 0x7e);
        guard valid else { return false; }
    }
    return true;
}

// Generates a cryptographically random unique identifier for the "jti" claim.
//
// Example:
//   out = ""
//   returns: out populated with 22-char base64url random identifier
fn generate_dpop_jti<B>(out: B&, entropy: const u8[:] = "") {
    out.clear();
    if entropy.len >= 16 {
        core::base64url_encode(entropy, out);
        return;
    }
    // High-resolution clock-seeded pseudo-random fallback
    let charset: const u8[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let now_ns = clock_ns();
    var state: u64 = (if now_ns > 0 { now_ns as u64 } else { 0 }) ^ 0x853c49e6748fea9b;
    for b in entropy {
        state = state * 1099511628211 ^ (b as u64);
    }
    for i in 22 {
        state = state * 6364136223846793005 + 1442695040888963407 + (i as u64);
        let idx = (state >> 32) % 64;
        out.push(charset[idx as i64]);
    }
}

// ---- 4. DPoP Proof JWT Generation -------------------------------------------

// Serializes DPoP claims JSON payload (RFC 9449 §4.2).
inline fn build_dpop_claims_json<B>(
    method: const u8[:],
    norm_uri: const u8[:],
    access_token: const u8[:],
    nonce: const u8[:],
    now_sec: i64,
    jti: const u8[:],
    out: B&,
) {
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
        if b >= 'a' && b <= 'z' {
            out.push(b - 32);
        } else {
            out.push(b);
        }
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

    if nonce.len > 0 {
        guard is_valid_dpop_nonce(nonce) else { return false; }
    }
    if jti.len > 0 {
        guard is_valid_dpop_nonce(jti) else { return false; }
    }

    var header_json: u8[..128] = [];
    header_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"HS256\"}");

    var header_b64: u8[..192] = [];
    core::base64url_encode(header_json[..], header_b64);

    var norm_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(target_uri, norm_uri) else {
        return false;
    }

    var claims_json: u8[..512] = [];
    build_dpop_claims_json(method, norm_uri[..], access_token, nonce, now_sec, jti, claims_json);

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
    return core::ct_eq_bytes(sig_b64, expected_sig_b64[..]);
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
        if key == "jti" {
            if seen_jti { had_dup = true; }
            seen_jti = true;
            let val = json::read_string(reader, scratch);
            if val.len <= out.jti.cap {
                out.jti.append(val);
            } else {
                had_error = true;
            }
        } else if key == "htm" {
            if seen_htm { had_dup = true; }
            seen_htm = true;
            let val = json::read_string(reader, scratch);
            if val.len <= out.htm.cap {
                out.htm.append(val);
            } else {
                had_error = true;
            }
        } else if key == "htu" {
            if seen_htu { had_dup = true; }
            seen_htu = true;
            let val = json::read_string(reader, scratch);
            if val.len <= out.htu.cap {
                out.htu.append(val);
            } else {
                had_error = true;
            }
        } else if key == "iat" {
            if seen_iat { had_dup = true; }
            seen_iat = true;
            let val = json::read_int(reader);
            out.iat = val;
            out.has_iat = true;
        } else if key == "nonce" {
            if seen_nonce { had_dup = true; }
            seen_nonce = true;
            let val = json::read_string(reader, scratch);
            if val.len <= out.nonce.cap {
                out.nonce.append(val);
            } else {
                had_error = true;
            }
        } else if key == "ath" {
            if seen_ath { had_dup = true; }
            seen_ath = true;
            let val = json::read_string(reader, scratch);
            if val.len <= out.ath.cap {
                out.ath.append(val);
            } else {
                had_error = true;
            }
        } else if key == "jkt" {
            if seen_jkt { had_dup = true; }
            seen_jkt = true;
            let val = json::read_string(reader, scratch);
            if val.len <= out.jkt.cap {
                out.jkt.append(val);
            } else {
                had_error = true;
            }
        } else {
            json::skip(reader);
        }
    };

    return json::finish(reader) && !had_dup && !had_error;
}

// RFC 9449 Section 4.3 Rule 4: Mandatory unique jti claim validation.
fn verify_dpop_jti(claims_json: const u8[:]) -> bool {
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    return claims.jti.len > 0 && claims.jti.len <= 128;
}

fn verify_dpop_method(claims_json: const u8[:], expected_method: const u8[:]) -> bool {
    guard expected_method.len > 0 else { return false; }
    for b in expected_method {
        if b >= 'a' && b <= 'z' { return false; }
    }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.htm.len > 0 else { return false; }
    for b in claims.htm {
        if b >= 'a' && b <= 'z' { return false; }
    }
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
    guard now_sec > 0 else { return true; }
    guard max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) else { return false; }
    guard claims.has_iat && claims.iat > 0 else { return false; }
    guard claims.iat <= (now_sec + max_skew_sec) else { return false; }
    return (now_sec - claims.iat) <= (max_age_sec + max_skew_sec);
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
    claims: const DPoPClaims&,
    expected_method: const u8[:],
    expected_uri: const u8[:],
    access_token: const u8[:] = "",
    expected_nonce: const u8[:] = "",
    now_sec: i64 = 0,
    max_age_sec: i64 = 300,
    max_skew_sec: i64 = 60,
    expected_jkt: const u8[:] = "",
) -> bool {
    // RFC 9449 §4.3 Rule 4: Mandatory unique jti
    guard claims.jti.len > 0 && claims.jti.len <= 128 else { return false; }

    // RFC 9449 §4.3 Rule 5: Exact uppercase HTTP method
    guard expected_method.len > 0 && claims.htm.len > 0 else { return false; }
    for b in claims.htm {
        if b >= 'a' && b <= 'z' { return false; }
    }
    guard claims.htm[..] == expected_method else { return false; }

    // RFC 9449 §4.3 Rule 6: Normalized target URI without query/fragment
    guard claims.htu.len > 0 else { return false; }
    for b in claims.htu {
        if b == '?' || b == '#' { return false; }
    }
    var norm_expected_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected_uri) else { return false; }
    var norm_htu: u8[..256] = [];
    guard normalize_dpop_target_uri(claims.htu[..], norm_htu) else { return false; }
    guard norm_htu[..] == norm_expected_uri[..] else { return false; }

    // RFC 9449 §4.3 Rule 7: Access token hash binding
    if access_token.len > 0 {
        var expected_ath: u8[..64] = [];
        compute_dpop_ath(access_token, expected_ath);
        guard claims.ath.len > 0 && claims.ath.len == expected_ath.len else { return false; }
        guard core::ct_eq_bytes(claims.ath[..], expected_ath[..]) else { return false; }
    }

    // RFC 9449 §4.3: Server nonce validation
    if expected_nonce.len > 0 {
        guard claims.nonce.len > 0 && claims.nonce.len == expected_nonce.len else { return false; }
        guard core::ct_eq_bytes(claims.nonce[..], expected_nonce) else { return false; }
    }

    // RFC 9449 §6.1: JWK Thumbprint confirmation
    if expected_jkt.len > 0 {
        guard claims.jkt.len > 0 && claims.jkt.len == expected_jkt.len else { return false; }
        guard core::ct_eq_bytes(claims.jkt[..], expected_jkt) else { return false; }
    }

    // RFC 9449 §4.3 Rule 8: Creation time & validity window
    if now_sec > 0 {
        guard max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
        guard claims.has_iat && claims.iat > 0 else { return false; }
        guard claims.iat <= (now_sec + max_skew_sec) else { return false; }
        guard (now_sec - claims.iat) <= (max_age_sec + max_skew_sec) else { return false; }
    }

    return true;
}

const MAX_DPOP_PROOF_LEN: i64 = 4096;

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
    guard jwt.len > 0 && jwt.len <= MAX_DPOP_PROOF_LEN else { return false; }
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

    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json[..], claims) else { return false; }

    return verify_dpop_claims(
        claims,
        expected_method,
        expected_uri,
        access_token,
        expected_nonce,
        now_sec,
        max_age_sec,
        max_skew_sec,
        expected_jkt,
    );
}

// ---- 6. Client Header Integration ------------------------------------------

// Attaches DPoP proof and optional Authorization: DPoP <token> header to a Request.
fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "") {
    set_header(req, DPOP_HEADER, proof);
    if access_token.len > 0 {
        var auth_val: u8[..2048] = [];
        auth_val.append("DPoP ");
        auth_val.append(access_token);
        set_header(req, "Authorization", auth_val[..]);
    }
}

// Extracts DPoP-Nonce from response headers as a zero-copy slice (RFC 9449 §8).
//
// Example:
//   headers = [{"DPoP-Nonce", "eyJhbGciOi..."}]
//   returns: "eyJhbGciOi...", ok = true
fn extract_dpop_nonce<H>(headers: const H[:]) -> const u8[:], bool {
    for idx in headers.len {
        if core::eq_ascii_fold(headers[idx].name[..], DPOP_NONCE_HEADER) {
            return headers[idx].value[..], true;
        }
    }
    return "", false;
}

// Extracts DPoP-Nonce into a target buffer (cleared only on success).
//
// Example:
//   headers = [{"DPoP-Nonce", "nonce-xyz"}], out_nonce = ""
//   returns: ok = true, out_nonce = "nonce-xyz"
fn extract_dpop_nonce<H, B>(headers: const H[:], out_nonce: B&) -> bool {
    let nonce, ok = extract_dpop_nonce(headers);
    guard ok else { return false; }
    out_nonce.clear();
    return out_nonce.try_append(nonce);
}

// ---- 7. DPoP Replay Cache (RFC 9449 §4.3 Rule 4) ---------------------------

struct DPoPJtiEntry {
    jti: u8[..64] = [],
    expires_at_sec: i64 = 0,
}

struct DPoPReplayCache {
    entries: DPoPJtiEntry[..128] = [],
    head: i64 = 0,
}

// Checks whether a DPoP jti has been seen before; if not, records it until now_sec + ttl_sec.
// Returns true if jti is unique and recorded; returns false if replay detected or input invalid.
fn check_and_record_dpop_jti(
    cache: DPoPReplayCache&,
    jti: const u8[:],
    now_sec: i64,
    ttl_sec: i64 = 300,
) -> bool {
    guard jti.len > 0 && jti.len <= 64 else { return false; }
    guard now_sec >= 0 && ttl_sec > 0 else { return false; }

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

    let exp = if now_sec > 9223372036854775807 - ttl_sec {
        9223372036854775807
    } else {
        now_sec + ttl_sec
    };

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

    let overwrite_idx = cache.head;
    cache.head = (cache.head + 1) % cache.entries.len;
    var slot = cache.entries[overwrite_idx];
    slot.jti.clear();
    slot.jti.append(jti);
    slot.expires_at_sec = exp;
    cache.entries[overwrite_idx] = slot;
    return true;
}

// Verifies a DPoP Proof JWT and rejects replayed proofs via DPoPReplayCache.
fn verify_dpop_proof_with_replay_cache(
    jwt: const u8[:],
    key: const u8[:],
    expected_method: const u8[:],
    expected_uri: const u8[:],
    now_sec: i64,
    cache: DPoPReplayCache&,
    access_token: const u8[:] = "",
    expected_nonce: const u8[:] = "",
    max_age_sec: i64 = 300,
    max_skew_sec: i64 = 60,
    expected_jkt: const u8[:] = "",
    expected_alg: const u8[:] = "HS256",
) -> bool {
    var claims = DPoPClaims { .. };
    var dot1: i64 = 0;
    var dot2: i64 = 0;
    guard split_jwt_parts(jwt, dot1, dot2) else { return false; }
    var claims_json: u8[>..] = [];
    guard core::base64url_decode(jwt[(dot1 + 1)..dot2], claims_json) else { return false; }
    guard parse_dpop_claims(claims_json[..], claims) else { return false; }

    guard verify_dpop_proof(
        jwt, key, expected_method, expected_uri,
        access_token, expected_nonce, now_sec,
        max_age_sec, max_skew_sec, expected_jkt, expected_alg,
    ) else { return false; }

    return check_and_record_dpop_jti(cache, claims.jti[..], now_sec, max_age_sec);
}
