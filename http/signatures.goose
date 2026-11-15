// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9421 HTTP Message Signatures (obsoleting all previous draft-cavage specifications).
// Provides end-to-end cryptographic signing and verification of HTTP message components
// using RFC 8941 Structured Fields formatting for Signature-Input and Signature headers.
// Supports HMAC-SHA256 and Ed25519, request and response signing, and component parameters.
namespace wing;

import std;
import core from "..";
import .request;
import .response;
import .sfv;

// ---- RFC 9421 Constants --------------------------------------------------

struct HttpSignatureParams {
    label:      u8[..32]       = "sig1",
    key_id:     u8[..64]       = [],
    alg:        u8[..32]       = "hmac-sha256",
    created:    i64            = 0,
    expires:    i64            = 0,
    nonce:      u8[..64]       = [],
    components: u8[..32][..16] = [],
}

// ---- Helper Functions & Port Inspection -----------------------------------

fn is_default_port(scheme: const u8[:], port: i32) -> bool {
    if port <= 0 { return true; }
    if scheme.eq_ascii_fold("http") && port == 80 { return true; }
    if scheme.eq_ascii_fold("https") && port == 443 { return true; }
    if scheme.eq_ascii_fold("ws") && port == 80 { return true; }
    if scheme.eq_ascii_fold("wss") && port == 443 { return true; }
    return false;
}

// RFC 9421 Section 2.1: HTTP Fields - Component names MUST be lowercased and MUST NOT be @signature-params.
fn is_valid_component_name(comp: const u8[:]) -> bool {
    guard comp.len > 0 && comp != "@signature-params" && comp != "@signature-params;req" else {
        return false;
    }
    for b in comp {
        if b >= 'A' && b <= 'Z' {
            return false;
        }
    }
    return true;
}

fn has_duplicate_component_before(
    components: const u8[..32][..16]&,
    limit:      i64,
    comp:       const u8[:],
) -> bool {
    for j in limit {
        if components[j][..] == comp {
            return true;
        }
    }
    return false;
}

// RFC 9421 Section 2.5: Creating the Signature Base - Component identifiers MUST be unique and lowercase.
fn has_valid_unique_components(components: const u8[..32][..16]&) -> bool {
    for i in components.len {
        let comp = components[i][..];
        guard is_valid_component_name(comp) && !has_duplicate_component_before(components, i, comp) else {
            return false;
        }
    }
    return true;
}

// Extracts special URL components (@authority, @path, @query, @scheme) per RFC 9421 §2.2.6.
//
// Example:
//   url_str = "https://example.com/foo?bar=1", comp = "@authority"
//   returns: true, out populated with "example.com"
fn extract_url_component<B>(url_str: const u8[:], comp: const u8[:], out: B&) -> bool {
    out.clear();
    guard is_valid_component_name(comp) else { return false; }
    let view, err = core::parse_url_view(url_str);
    let _ = err;
    guard view.valid else { return false; }
    if comp == "@authority" {
        guard out.try_append(view.host) else {
            out.clear();
            return false;
        }
        to_lower(out[..]);
        if view.port > 0 && !is_default_port(view.scheme, view.port) {
            var pbuf: u8[..16] = [];
            view.port.format_i64_dec(pbuf);
            guard out.try_push(':') && out.try_append(pbuf[..]) else {
                out.clear();
                return false;
            }
        }
        return true;
    }
    if comp == "@path" {
        let p = if view.pathname.len > 0 { view.pathname } else { "/" };
        guard out.try_set(p) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@query" {
        let q = if view.search.len > 0 { view.search } else { "?" };
        guard out.try_set(q) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@request-target" {
        let p = if view.pathname.len > 0 { view.pathname } else { "/" };
        guard out.try_append(p) && (view.search.len == 0 || out.try_append(view.search)) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@scheme" {
        guard out.try_set(view.scheme) else {
            out.clear();
            return false;
        }
        to_lower(out[..]);
        return true;
    }
    return false;
}

// RFC 9421 Section 2.1: HTTP Fields - Strip leading/trailing OWS and fold obs-fold CRLF+WSP to SP while preserving internal whitespace.
//
// Example:
//   s = "a\r\n   b", start = 1
//   returns: next = 6 (points to 'b'), ok = true
inline fn consume_obs_fold_wsp(s: const u8[:], start: i64) -> i64, bool {
    let lf_idx = core::add_sat_i64(start, 1);
    let ws_start = core::add_sat_i64(start, 2);
    guard ws_start < s.len && s[lf_idx] == '\n' && core::is_lws(s[ws_start]) else {
        return start, false;
    }
    var next = core::add_sat_i64(ws_start, 1);
    while next < s.len && core::is_lws(s[next]) {
        next = core::add_sat_i64(next, 1);
    }
    return next, true;
}

fn normalize_header_value<B>(val: const u8[:], out: B&) -> bool {
    let trimmed = val.trim_lws_start().trim_end_bytes(" \t\r\n");
    if trimmed.len == 0 {
        return true;
    }
    var i: i64 = 0;
    while i < trimmed.len {
        let ch = trimmed[i];
        if ch == '\r' {
            let next_i, ok_fold = consume_obs_fold_wsp(trimmed, i);
            guard ok_fold && out.try_push(' ' as u8) else {
                out.clear();
                return false;
            }
            i = next_i;
            continue;
        }
        guard ch != '\n' && out.try_push(ch) else {
            out.clear();
            return false;
        }
        i = core::add_sat_i64(i, 1);
    }
    return true;
}

// Extracts and concatenates comma-separated header field values (RFC 9421 §2.1).
//
// Example:
//   headers = [{"date", "Tue, 20 Apr 2021"}], name = "date"
//   returns: true, out = "Tue, 20 Apr 2021"
fn extract_combined_header_value<B>(headers: const HeaderMap&, name: const u8[:], out: B&) -> bool {
    guard is_valid_component_name(name) else {
        out.clear();
        return false;
    }
    var found = false;
    for &e in headers.entries {
        guard entry_name(headers, e).eq_ascii_fold(name) else { continue; }
        var norm_buf: u8[..4096] = [];
        guard normalize_header_value(entry_value(headers, e), norm_buf) else {
            out.clear();
            return false;
        }
        if found {
            guard out.try_append(", ") else {
                out.clear();
                return false;
            }
        }
        guard out.try_append(norm_buf[..]) else {
            out.clear();
            return false;
        }
        found = true;
    }
    return found;
}

// Extracts component value per RFC 9421 Section 2.
//
// Example:
//   req has method "GET", comp = "@method"
//   returns: true, out populated with "GET"
fn extract_component_value<B>(req: const Request&, comp: const u8[:], out: B&) -> bool {
    guard is_valid_component_name(comp) else {
        out.clear();
        return false;
    }
    if comp == "@method" {
        guard out.try_set(req.method[..]) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@target-uri" {
        guard out.try_set(req.url[..]) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp.len > 0 && comp[0] == '@' {
        return extract_url_component(req.url[..], comp, out);
    }
    out.clear();
    return extract_combined_header_value(req.headers, comp, out);
}

fn strip_req_component_suffix(comp: const u8[:]) -> const u8[:], bool {
    guard comp.len > 4 && comp[^4..] == ";req" else { return comp, false; }
    return comp[..^4], true;
}

// Extracts component value from Response (RFC 9421 §2.2), supporting @status and ";req" parameters.
//
// Example:
//   res has status 200, comp = "@status"
//   returns: true, out populated with "200"
fn extract_response_component_value<B>(
    res:  const Response&,
    req:  const Request&,
    comp: const u8[:],
    out:  B&,
) -> bool {
    out.clear();
    guard is_valid_component_name(comp) else { return false; }
    if comp == "@status" {
        var st_buf: u8[..16] = [];
        res.status_code.format_i64_dec(st_buf);
        return out.try_set(st_buf[..]);
    }
    let req_comp, is_req = strip_req_component_suffix(comp);
    if is_req {
        return extract_component_value(req, req_comp, out);
    }
    return extract_combined_header_value(res.headers, comp, out);
}

fn append_escaped_string_param<B>(s: const u8[:], out: B&) -> bool {
    for b in s {
        if (b == '"' || b == '\\') && !out.try_push('\\' as u8) {
            return false;
        }
        guard out.try_push(b) else { return false; }
    }
    return true;
}

fn append_named_sig_int_param<B>(key: const u8[:], val: i64, out: B&) -> bool {
    var ibuf: u8[..24] = [];
    val.format_i64_dec(ibuf);
    return out.try_push(';' as u8) && out.try_append(key) && out.try_push('=' as u8) && out.try_append(ibuf[..]);
}

fn append_named_sig_str_param<B>(key: const u8[:], val: const u8[:], out: B&) -> bool {
    guard out.try_push(';' as u8) && out.try_append(key) && out.try_append("=\"") else { return false; }
    return append_escaped_string_param(val, out) && out.try_push('"' as u8);
}

// Formats the "@signature-params" inner-list and parameters (RFC 9421 Section 2.5)
fn format_signature_params<B>(params: const HttpSignatureParams&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_push('(' as u8) else { return false; }
    for idx in params.components.len {
        if idx > 0 && !out.try_push(' ' as u8) { return false; }
        let base_comp, has_req = strip_req_component_suffix(params.components[idx][..]);
        guard out.try_push('"' as u8) && out.try_append(base_comp) && out.try_push('"' as u8) else {
            return false;
        }
        if has_req && !out.try_append(";req") { return false; }
    }
    guard out.try_push(')' as u8) else { return false; }

    if params.created > 0 && !append_named_sig_int_param("created", params.created, out) { return false; }
    if params.expires > 0 && !append_named_sig_int_param("expires", params.expires, out) { return false; }
    if params.key_id.len > 0 && !append_named_sig_str_param("keyid", params.key_id[..], out) { return false; }
    if params.alg.len > 0 && !append_named_sig_str_param("alg", params.alg[..], out) { return false; }
    if params.nonce.len > 0 && !append_named_sig_str_param("nonce", params.nonce[..], out) { return false; }
    committed = true;
    return true;
}

// ---- Signature Base Generation (RFC 9421 Section 2.5) --------------------

fn build_signature_base_from_params_line<B>(
    req:             const Request&,
    components:      const u8[..32][..16]&,
    sig_params_line: const u8[:],
    out:             B&,
) -> bool {
    out.clear();
    guard has_valid_unique_components(components) else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    for idx in components.len {
        let comp = components[idx][..];
        var val: u8[..4096] = [];
        guard extract_component_value(req, comp, val) else { return false; }
        guard out.try_push('"' as u8) &&
              out.try_append(comp) &&
              out.try_append("\": ") &&
              out.try_append(val[..]) &&
              out.try_push('\n' as u8) else {
            return false;
        }
    }
    guard out.try_append("\"@signature-params\": ") && out.try_append(sig_params_line) else { return false; }
    committed = true;
    return true;
}

fn build_signature_base<B>(
    req:    const Request&,
    params: const HttpSignatureParams&,
    out:    B&,
) -> bool {
    out.clear();
    var sp_line: u8[..2048] = [];
    guard format_signature_params(params, sp_line) else { return false; }
    return build_signature_base_from_params_line(req, params.components, sp_line[..], out);
}

fn build_response_signature_base_from_params_line<B>(
    res:             const Response&,
    req:             const Request&,
    components:      const u8[..32][..16]&,
    sig_params_line: const u8[:],
    out:             B&,
) -> bool {
    out.clear();
    guard has_valid_unique_components(components) else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    for idx in components.len {
        let comp = components[idx][..];
        var val: u8[..4096] = [];
        guard extract_response_component_value(res, req, comp, val) else { return false; }
        let base_comp, has_req = strip_req_component_suffix(comp);
        guard out.try_push('"' as u8) && out.try_append(base_comp) && out.try_push('"' as u8) else {
            return false;
        }
        if has_req && !out.try_append(";req") { return false; }
        guard out.try_append(": ") && out.try_append(val[..]) && out.try_push('\n' as u8) else {
            return false;
        }
    }
    guard out.try_append("\"@signature-params\": ") && out.try_append(sig_params_line) else { return false; }
    committed = true;
    return true;
}

fn build_response_signature_base<B>(
    res:    const Response&,
    req:    const Request&,
    params: const HttpSignatureParams&,
    out:    B&,
) -> bool {
    out.clear();
    var sp_line: u8[..2048] = [];
    guard format_signature_params(params, sp_line) else { return false; }
    return build_response_signature_base_from_params_line(res, req, params.components, sp_line[..], out);
}

// ---- Cryptographic Engine (HMAC-SHA256, Ed25519, ECDSA-P256, RSA) --------

// Default in-memory key wrapper for UFCS `<Signer>` and `<Verifier>` injection.
struct MemoryKeySigner {
    key: u8[..1024] = [],
}

// Constructs a `MemoryKeySigner` with bounded key material (`<= 1024` bytes).
fn new_memory_key_signer(raw_key: const u8[:]) -> MemoryKeySigner, bool {
    var s = MemoryKeySigner { .. };
    guard raw_key.len > 0 && s.key.try_set(raw_key) else {
        return s, false;
    }
    return s, true;
}

// Zeroizes and clears secret key bytes in `MemoryKeySigner`.
fn clear_memory_key_signer(s: MemoryKeySigner&) {
    core::secure_zeroize_slice(s.key[..]);
    s.key.clear();
}

fn compute_rsa_raw_signature(
    alg:        const u8[:],
    secret_key: const u8[:],
    sig_base:   const u8[:],
    out_sig:    u8[..512]&,
) -> bool {
    out_sig.clear();
    let klen = secret_key.len;
    guard klen > 0 && (klen & 1) == 0 else { return false; }
    let half = klen >> 1;
    if alg == rfc::SIG_ALG_RSA_V1_5_SHA256 {
        guard klen >= 128 &&
              core::rsa_pkcs1_sha256_sign(secret_key[..half], secret_key[half..], sig_base, out_sig) else {
            out_sig.clear();
            return false;
        }
        return true;
    }
    if alg == rfc::SIG_ALG_RSA_PSS_SHA512 {
        let salt64 = core::sha512(sig_base);
        guard klen >= 256 &&
              core::rsa_pss_sha512_sign(secret_key[..half], secret_key[half..], salt64[..], sig_base, out_sig) else {
            out_sig.clear();
            return false;
        }
        return true;
    }
    return false;
}

// Computes raw binary signature bytes for RFC 9421 `alg` over `sig_base`.
fn compute_raw_signature(
    alg:        const u8[:],
    secret_key: const u8[:],
    sig_base:   const u8[:],
    out_sig:    u8[..512]&,
) -> bool {
    out_sig.clear();
    let klen = secret_key.len;
    if alg == rfc::SIG_ALG_ED25519 {
        guard klen == 32 else { return false; }
        var seed_arr: u8[32] = [0; 32];
        for i in 32 { seed_arr[i] = secret_key[i]; }
        let ed_sig = core::ed25519_sign(seed_arr, sig_base);
        core::secure_zeroize_32(seed_arr);
        return out_sig.try_set(ed_sig[..]);
    } else if alg == rfc::SIG_ALG_ECDSA_P256_SHA256 {
        guard klen == 32 else { return false; }
        var priv_arr: u8[32] = [0; 32];
        for i in 32 { priv_arr[i] = secret_key[i]; }
        let ec_sig = core::ecdsa_p256_sign(priv_arr, sig_base);
        core::secure_zeroize_32(priv_arr);
        return out_sig.try_set(ec_sig[..]);
    } else if alg == rfc::SIG_ALG_HMAC_SHA256 {
        let hmac_sig = core::hmac_sha256(secret_key, sig_base);
        return out_sig.try_set(hmac_sig[..]);
    }
    return compute_rsa_raw_signature(alg, secret_key, sig_base, out_sig);
}

// UFCS `<Signer>` implementation for `MemoryKeySigner`.
fn sign_message(
    signer:  const MemoryKeySigner&,
    alg:     const u8[:],
    tbs:     const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard signer.key.len > 0 else {
        out_sig.clear();
        return false;
    }
    return compute_raw_signature(alg, signer.key[..], tbs, out_sig);
}

// UFCS `<Verifier>` implementation for `MemoryKeySigner`.
fn verify_message(
    signer:       const MemoryKeySigner&,
    alg:          const u8[:],
    tbs:          const u8[:],
    received_sig: const u8[:],
) -> bool {
    guard signer.key.len > 0 else { return false; }
    return verify_crypto_signature(alg, signer.key[..], tbs, received_sig);
}

fn verify_crypto_signature(
    alg:          const u8[:],
    key_bytes:    const u8[:],
    sig_base:     const u8[:],
    received_sig: const u8[:],
) -> bool {
    if alg == rfc::SIG_ALG_ED25519 {
        guard key_bytes.len == 32 && received_sig.len == 64 else { return false; }
        var pub_arr: u8[32] = [0; 32];
        for i in 32 { pub_arr[i] = key_bytes[i]; }
        var sig_arr: u8[64] = [0; 64];
        for i in 64 { sig_arr[i] = received_sig[i]; }
        return core::ed25519_verify(pub_arr, sig_base, sig_arr);
    } else if alg == rfc::SIG_ALG_ECDSA_P256_SHA256 {
        guard received_sig.len == 64 else { return false; }
        return core::ecdsa_p256_verify_p1363(key_bytes, sig_base, received_sig);
    } else if alg == rfc::SIG_ALG_RSA_V1_5_SHA256 {
        if key_bytes.len > 0 && key_bytes[0] == 0x30 {
            return core::rsa_pkcs1_sha256_verify_der(key_bytes, sig_base, received_sig);
        }
        let default_e: const u8[3] = [0x01, 0x00, 0x01];
        return core::rsa_pkcs1_sha256_verify(key_bytes, default_e[..], sig_base, received_sig);
    } else if alg == rfc::SIG_ALG_RSA_PSS_SHA512 {
        let default_e: const u8[3] = [0x01, 0x00, 0x01];
        return core::rsa_pss_sha512_verify(key_bytes, default_e[..], sig_base, received_sig);
    } else if alg == rfc::SIG_ALG_HMAC_SHA256 {
        let expected_sig = core::hmac_sha256(key_bytes, sig_base);
        guard received_sig.len == expected_sig.len else { return false; }
        return core::ct_eq_bytes(received_sig, expected_sig[..]);
    }
    return false;
}

// Parses an RFC 8941 Structured Fields Dictionary for Signature header using SfType.Binary.
//
// Example:
//   header_val = "sig1=:ZXhhbXBsZQ==:", label = "sig1"
//   returns: "ZXhhbXBsZQ==", ok = true
fn extract_signature_value(header_val: const u8[:], label: const u8[:]) -> const u8[:], bool {
    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(header_val, entries) else { return "", false; }
    for &entry in entries {
        if entry.key == label && entry.item.kind == SfType.Binary {
            return entry.item.str_val, true;
        }
    }
    return "", false;
}

// RFC 9421 Section 2.3: Signature Parameters - Reject negative timestamps and enforce clock skew.
fn validate_signature_created(created: i64, expires: i64, now_sec: i64) -> bool {
    guard created >= 0 && expires >= 0 else { return false; }
    if created > 0 && expires > 0 {
        guard created < expires else { return false; }
    }
    if created > 0 && now_sec > 0 {
        guard core::add_sat_i64(now_sec, 60) >= created else { return false; }
    }
    return true;
}

fn validate_signature_expires(expires: i64, now_sec: i64) -> bool {
    guard expires >= 0 else { return false; }
    if expires > 0 && now_sec > 0 {
        guard core::sub_sat_i64(now_sec, 60) <= expires else { return false; }
    }
    return true;
}

fn validate_signature_timestamps(params: const HttpSignatureParams&, now_sec: i64) -> bool {
    guard validate_signature_created(params.created, params.expires, now_sec) else { return false; }
    return validate_signature_expires(params.expires, now_sec);
}

fn format_signature_header_value<B>(label: const u8[:], b64_sig: const u8[:], out: B&) -> bool {
    out.clear();
    guard out.try_append(label) && out.try_append("=:") && out.try_append(b64_sig) && out.try_push(':') else {
        out.clear();
        return false;
    }
    return true;
}

fn format_signature_input_header_value<B>(params: const HttpSignatureParams&, out: B&) -> bool {
    out.clear();
    guard out.try_append(params.label[..]) && out.try_push('=') && format_signature_params(params, out) else {
        out.clear();
        return false;
    }
    return true;
}

fn attach_request_signature_headers(req: Request&, params: const HttpSignatureParams&, b64_sig: const u8[:]) -> bool {
    var input_hdr: u8[..4096] = [];
    var sig_hdr:   u8[..4096] = [];
    guard format_signature_input_header_value(params, input_hdr) &&
          format_signature_header_value(params.label[..], b64_sig, sig_hdr) else {
        return false;
    }
    set_header(req, rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    set_header(req, rfc::HEADER_SIGNATURE, sig_hdr[..]);
    return true;
}

fn attach_response_signature_headers(res: Response&, params: const HttpSignatureParams&, b64_sig: const u8[:]) -> bool {
    var input_hdr: u8[..4096] = [];
    var sig_hdr:   u8[..4096] = [];
    guard format_signature_input_header_value(params, input_hdr) &&
          format_signature_header_value(params.label[..], b64_sig, sig_hdr) else {
        return false;
    }
    res.set_header(rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    res.set_header(rfc::HEADER_SIGNATURE, sig_hdr[..]);
    return true;
}

// ---- Request Signing & Verification --------------------------------------

// Signs an HTTP request using an injected UFCS `<Signer>` (HSM / PKCS#11 / CloudKMS).
fn sign_http_request_with<Signer>(
    req:    Request&,
    params: const HttpSignatureParams&,
    signer: Signer&,
) -> bool {
    guard validate_signature_timestamps(params, 0) else { return false; }
    var sig_base: u8[..4096] = [];
    guard build_signature_base(req, params, sig_base) else {
        return false;
    }

    var raw_sig: u8[..512] = [];
    guard signer.sign_message(params.alg[..], sig_base[..], raw_sig) else {
        return false;
    }

    var b64_sig: u8[..1024] = [];
    core::base64_encode(raw_sig[..], b64_sig);
    return attach_request_signature_headers(req, params, b64_sig[..]);
}

// Signs an HTTP request according to RFC 9421 and attaches Signature-Input and Signature headers.
fn sign_http_request(
    req:        Request&,
    params:     const HttpSignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var signer, ok_s = new_memory_key_signer(secret_key);
    guard ok_s else { return false; }
    defer clear_memory_key_signer(signer);
    return sign_http_request_with(req, params, signer);
}

fn matches_signature_component(item: const SfItem&, exp_comp: const u8[:]) -> bool {
    guard item.kind == SfType.String else { return false; }
    let has_req_param = sf_item_has_flag_param(item, "req");
    if !has_req_param && item.str_val == exp_comp {
        return true;
    }
    let base_comp, exp_has_req = strip_req_component_suffix(exp_comp);
    return has_req_param && exp_has_req && item.str_val == base_comp;
}

fn append_wire_sf_bare<B>(
    kind:     SfType,
    int_val:  i64,
    str_val:  const u8[:],
    bool_val: bool,
    out:      B&,
) -> bool {
    if kind == SfType.String {
        return out.try_push('"' as u8) && out.try_append(str_val) && out.try_push('"' as u8);
    }
    if kind == SfType.Integer {
        var ibuf: u8[..24] = [];
        int_val.format_i64_dec(ibuf);
        return out.try_append(ibuf[..]);
    }
    if kind == SfType.Boolean {
        return out.try_append(if bool_val { "?1" } else { "?0" });
    }
    if kind == SfType.Token {
        return out.try_append(str_val);
    }
    if kind == SfType.Binary {
        return out.try_push(':' as u8) && out.try_append(str_val) && out.try_push(':' as u8);
    }
    if kind == SfType.Decimal {
        var dbuf: u8[..32] = [];
        serialize_sfv_decimal(int_val, dbuf);
        return out.try_append(dbuf[..]);
    }
    if kind == SfType.Date {
        var dtbuf: u8[..24] = [];
        dtbuf.push('@' as u8);
        int_val.format_i64_dec(dtbuf);
        return out.try_append(dtbuf[..]);
    }
    return out.try_append("%\"") && out.try_append(str_val) && out.try_push('"' as u8);
}

fn append_wire_item_params<B>(params: const SfItemParam[:], out: B&) -> bool {
    for &p in params {
        guard out.try_push(';' as u8) && out.try_append(p.key[..]) else { return false; }
        if p.kind == SfType.Boolean && p.bool_val {
            continue;
        }
        guard out.try_push('=' as u8) &&
              append_wire_sf_bare(p.kind, p.int_val, p.str_val[..], p.bool_val, out) else {
            return false;
        }
    }
    return true;
}

fn append_wire_dict_params<B>(params: const SfParameter[:], out: B&) -> bool {
    for &p in params {
        guard out.try_push(';' as u8) && out.try_append(p.key) else { return false; }
        if p.item.kind == SfType.Boolean && p.item.bool_val {
            continue;
        }
        guard out.try_push('=' as u8) &&
              append_wire_sf_bare(p.item.kind, p.item.int_val, p.item.str_val, p.item.bool_val, out) else {
            return false;
        }
    }
    return true;
}

fn serialize_wire_sig_params<B>(entry: const SfDictEntry&, out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    guard out.try_push('(' as u8) else { return false; }
    for idx in entry.inner_items.len {
        if idx > 0 && !out.try_push(' ' as u8) { return false; }
        let it = &entry.inner_items[idx];
        guard append_wire_sf_bare(it.kind, it.int_val, it.str_val, it.bool_val, out) &&
              append_wire_item_params(it.params[..], out) else {
            return false;
        }
    }
    guard out.try_push(')' as u8) && append_wire_dict_params(entry.params[..], out) else {
        return false;
    }
    committed = true;
    return true;
}

inline fn sf_str_param_matches(item: const SfItem&, expected: const u8[:]) -> bool {
    var unq: u8[..128] = [];
    return item.kind == SfType.String && sf_unescape_string(item.str_val, unq) && unq[..] == expected;
}

fn check_sig_entry_param(
    p:            const SfParameter&,
    params:       const HttpSignatureParams&,
    seen_mask:    u32&,
    wire_created: i64&,
    wire_expires: i64&,
) -> bool {
    if p.key == "alg" {
        return sf_str_param_matches(p.item, params.alg[..]);
    }
    if p.key == "keyid" {
        guard sf_str_param_matches(p.item, params.key_id[..]) else { return false; }
        seen_mask = seen_mask | 1;
        return true;
    }
    if p.key == "created" {
        guard p.item.kind == SfType.Integer && p.item.int_val >= 0 &&
              (params.created == 0 || p.item.int_val == params.created) else {
            return false;
        }
        wire_created = p.item.int_val;
        seen_mask = seen_mask | 2;
        return true;
    }
    if p.key == "expires" {
        guard p.item.kind == SfType.Integer && p.item.int_val >= 0 &&
              (params.expires == 0 || p.item.int_val == params.expires) else {
            return false;
        }
        wire_expires = p.item.int_val;
        seen_mask = seen_mask | 4;
        return true;
    }
    if p.key == "nonce" {
        guard sf_str_param_matches(p.item, params.nonce[..]) else { return false; }
        seen_mask = seen_mask | 8;
        return true;
    }
    return true;
}

fn verify_sig_entry_match(
    entry:        const SfDictEntry&,
    params:       const HttpSignatureParams&,
    wire_created: i64&,
    wire_expires: i64&,
) -> bool {
    guard entry.inner_items.len == params.components.len else { return false; }
    for i in params.components.len {
        guard matches_signature_component(entry.inner_items[i], params.components[i][..]) else {
            return false;
        }
    }
    var seen_mask: u32 = 0;
    for &p in entry.params {
        guard check_sig_entry_param(p, params, seen_mask, wire_created, wire_expires) else {
            return false;
        }
    }
    if params.key_id.len > 0 && (seen_mask & 1) == 0 { return false; }
    if params.created > 0 && (seen_mask & 2) == 0 { return false; }
    if params.expires > 0 && (seen_mask & 4) == 0 { return false; }
    if params.nonce.len > 0 && (seen_mask & 8) == 0 { return false; }
    return true;
}

// RFC 9421 Section 3.2: Verifying a Signature - Match label, components, and wire parameters.
fn find_verified_sig_params_line<B>(
    sig_input_val:  const u8[:],
    label:          const u8[:],
    params:         const HttpSignatureParams&,
    out_sig_params: B&,
    out_created:    i64&,
    out_expires:    i64&,
) -> bool {
    out_sig_params.clear();
    out_created = 0;
    out_expires = 0;
    guard params.created >= 0 && params.expires >= 0 && has_valid_unique_components(params.components) else {
        return false;
    }
    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(sig_input_val, entries) else { return false; }
    for &entry in entries {
        guard entry.key == label && entry.is_inner_list else { continue; }
        var wc: i64 = 0;
        var we: i64 = 0;
        guard verify_sig_entry_match(entry, params, wc, we) &&
              serialize_wire_sig_params(entry, out_sig_params) else {
            out_sig_params.clear();
            return false;
        }
        out_created = wc;
        out_expires = we;
        return true;
    }
    return false;
}

fn verify_signature_input_label(
    sig_input_val: const u8[:],
    label:         const u8[:],
    params:        const HttpSignatureParams&,
) -> bool {
    var wire_sp: u8[..2048] = [];
    var wc:      i64        = 0;
    var we:      i64        = 0;
    return find_verified_sig_params_line(sig_input_val, label, params, wire_sp, wc, we);
}

fn validate_and_decode_signature_headers(
    headers:        const HeaderMap&,
    label:          const u8[:],
    params:         const HttpSignatureParams&,
    now_sec:        i64,
    out_sig_params: u8[..2048]&,
    out_sig:        u8[..512]&,
) -> bool {
    out_sig_params.clear();
    out_sig.clear();
    var comb_in: u8[..4096] = [];
    guard headers.get_header(rfc::HEADER_SIGNATURE_INPUT).len > 0 &&
          headers.get_combined(rfc::HEADER_SIGNATURE_INPUT, comb_in, 4096) else {
        return false;
    }
    var wire_created: i64 = 0;
    var wire_expires: i64 = 0;
    guard find_verified_sig_params_line(
        comb_in[..],
        label,
        params,
        out_sig_params,
        wire_created,
        wire_expires,
    ) else {
        return false;
    }
    guard validate_signature_created(wire_created, wire_expires, now_sec) &&
          validate_signature_expires(wire_expires, now_sec) else {
        out_sig_params.clear();
        return false;
    }

    var comb_sig: u8[..4096] = [];
    guard headers.get_header(rfc::HEADER_SIGNATURE).len > 0 &&
          headers.get_combined(rfc::HEADER_SIGNATURE, comb_sig, 4096) else {
        out_sig_params.clear();
        return false;
    }

    let received_b64, ok = extract_signature_value(comb_sig[..], label);
    guard ok && core::base64_decode(received_b64, out_sig) else {
        out_sig_params.clear();
        out_sig.clear();
        return false;
    }
    return true;
}

// Verifies an RFC 9421 signature on a Request using an injected UFCS `<Verifier>`.
fn verify_http_signature_with<Verifier>(
    req:      const Request&,
    label:    const u8[:],
    params:   const HttpSignatureParams&,
    verifier: Verifier&,
    now_sec:  i64 = 0,
) -> bool {
    guard label == params.label else { return false; }
    guard validate_signature_timestamps(params, now_sec) else { return false; }

    var wire_sig_params: u8[..2048] = [];
    var received_sig:    u8[..512]  = [];
    guard validate_and_decode_signature_headers(
        req.headers,
        label,
        params,
        now_sec,
        wire_sig_params,
        received_sig,
    ) else {
        return false;
    }

    var sig_base: u8[..4096] = [];
    guard build_signature_base_from_params_line(req, params.components, wire_sig_params[..], sig_base) else {
        return false;
    }

    return verifier.verify_message(params.alg[..], sig_base[..], received_sig[..]);
}

// Verifies an RFC 9421 signature on a Request.
fn verify_http_signature(
    req:       const Request&,
    label:     const u8[:],
    params:    const HttpSignatureParams&,
    key_bytes: const u8[:],
    now_sec:   i64 = 0,
) -> bool {
    var verifier, ok_v = new_memory_key_signer(key_bytes);
    guard ok_v else { return false; }
    defer clear_memory_key_signer(verifier);
    return verify_http_signature_with(req, label, params, verifier, now_sec);
}

// ---- Response Signing & Verification -------------------------------------

// Signs an HTTP response using an injected UFCS `<Signer>` (HSM / PKCS#11 / CloudKMS).
fn sign_http_response_with<Signer>(
    res:    Response&,
    req:    const Request&,
    params: const HttpSignatureParams&,
    signer: Signer&,
) -> bool {
    guard validate_signature_timestamps(params, 0) else { return false; }
    var sig_base: u8[..4096] = [];
    guard build_response_signature_base(res, req, params, sig_base) else {
        return false;
    }

    var raw_sig: u8[..512] = [];
    guard signer.sign_message(params.alg[..], sig_base[..], raw_sig) else {
        return false;
    }

    var b64_sig: u8[..1024] = [];
    core::base64_encode(raw_sig[..], b64_sig);
    return attach_response_signature_headers(res, params, b64_sig[..]);
}

// Signs an HTTP response according to RFC 9421.
fn sign_http_response(
    res:        Response&,
    req:        const Request&,
    params:     const HttpSignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var signer, ok_s = new_memory_key_signer(secret_key);
    guard ok_s else { return false; }
    defer clear_memory_key_signer(signer);
    return sign_http_response_with(res, req, params, signer);
}

// Verifies an RFC 9421 signature on a Response using an injected UFCS `<Verifier>`.
fn verify_http_response_signature_with<Verifier>(
    res:      const Response&,
    req:      const Request&,
    label:    const u8[:],
    params:   const HttpSignatureParams&,
    verifier: Verifier&,
    now_sec:  i64 = 0,
) -> bool {
    guard label == params.label else { return false; }
    guard validate_signature_timestamps(params, now_sec) else { return false; }

    var wire_sig_params: u8[..2048] = [];
    var received_sig:    u8[..512]  = [];
    guard validate_and_decode_signature_headers(
        res.headers,
        label,
        params,
        now_sec,
        wire_sig_params,
        received_sig,
    ) else {
        return false;
    }

    var sig_base: u8[..4096] = [];
    guard build_response_signature_base_from_params_line(
        res,
        req,
        params.components,
        wire_sig_params[..],
        sig_base,
    ) else {
        return false;
    }

    return verifier.verify_message(params.alg[..], sig_base[..], received_sig[..]);
}

// Verifies an RFC 9421 signature on a Response.
fn verify_http_response_signature(
    res:       const Response&,
    req:       const Request&,
    label:     const u8[:],
    params:    const HttpSignatureParams&,
    key_bytes: const u8[:],
    now_sec:   i64 = 0,
) -> bool {
    var verifier, ok_v = new_memory_key_signer(key_bytes);
    guard ok_v else { return false; }
    defer clear_memory_key_signer(verifier);
    return verify_http_response_signature_with(res, req, label, params, verifier, now_sec);
}

// ---- High-Level Convenience Helpers --------------------------------------

// Signs request with RFC 9421 HTTP Message Signatures using Ed25519.
// Automatically configures standard component identifiers (@method, @authority, @path, @query).
fn sign_request_ed25519(req: Request&, key_id: const u8[:], private_key: const u8[:]) -> bool {
    var params = HttpSignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@method");
    params.components.push("@authority");
    params.components.push("@path");
    params.components.push("@query");
    return sign_http_request(req, params, private_key);
}

// Verifies request signature using Ed25519 public key and key_id.
fn verify_request_ed25519(req: const Request&, key_id: const u8[:], public_key: const u8[:]) -> bool {
    var params = HttpSignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@method");
    params.components.push("@authority");
    params.components.push("@path");
    params.components.push("@query");
    return verify_http_signature(req, "sig1", params, public_key);
}

// Signs response with RFC 9421 HTTP Message Signatures using Ed25519.
// Automatically configures standard component identifiers (@status, content-type).
fn sign_response_ed25519(
    res:         Response&,
    req:         const Request&,
    key_id:      const u8[:],
    private_key: const u8[:],
) -> bool {
    var params = HttpSignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@status");
    params.components.push("content-type");
    return sign_http_response(res, req, params, private_key);
}

// Verifies response signature using Ed25519 public key and key_id.
fn verify_response_ed25519(
    res:        const Response&,
    req:        const Request&,
    key_id:     const u8[:],
    public_key: const u8[:],
) -> bool {
    var params = HttpSignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@status");
    params.components.push("content-type");
    return verify_http_response_signature(res, req, "sig1", params, public_key);
}
