// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9421 HTTP Message Signatures (obsoleting all previous draft-cavage specifications).
// Provides end-to-end cryptographic signing and verification of HTTP message components
// using RFC 8941 Structured Fields formatting for Signature-Input and Signature headers.
// Supports HMAC-SHA256 and Ed25519, request and response signing, and component parameters.
namespace wing;

import std;
import core from "..";
import client.request;
import client.response;
import .sfv;

// ---- RFC 9421 Constants --------------------------------------------------

const HEADER_SIGNATURE_INPUT: const u8[:] = "Signature-Input";
const HEADER_SIGNATURE:       const u8[:] = "Signature";

const SIG_ALG_HMAC_SHA256: const u8[:] = "hmac-sha256";
const SIG_ALG_ED25519:     const u8[:] = "ed25519";

// ---- Signature Models ----------------------------------------------------

struct HttpSignatureParams {
    label:      u8[..32]       = "sig1",
    key_id:     u8[..64]       = [],
    alg:        u8[..32]       = "hmac-sha256",
    created:    i64            = 0,
    expires:    i64            = 0,
    nonce:      u8[..64]       = [],
    components: u8[..32][..16] = [],
}

// ---- Helper Functions & Proven Skew Arithmetic ---------------------------

fn sig_add_skew(t: i64) -> i64 {
    return t + 60;
}

fn sig_sub_skew(t: i64) -> i64 {
    return t - 60;
}

fn sig_sub_len(total: i64, sub: i64) -> i64 {
    return total - sub;
}

// Extracts special URL components (@authority, @path, @query, @scheme) per RFC 9421 §2.2.6.
//
// Example:
//   url_str = "https://example.com/foo?bar=1", comp = "@authority"
//   returns: true, out populated with "example.com"
fn extract_url_component(url_str: const u8[:], comp: const u8[:], out: u8[..1024]&) -> bool {
    let view, err = core::parse_url_view(url_str);
    guard view.valid else { return false; }
    if eq_ascii_fold(comp, "@authority") {
        out.append(view.host);
        return true;
    }
    if eq_ascii_fold(comp, "@path") {
        out.append(if view.pathname.len > 0 { view.pathname } else { "/" });
        return true;
    }
    if eq_ascii_fold(comp, "@query") {
        out.append(if view.search.len > 0 { view.search } else { "?" });
        return true;
    }
    if eq_ascii_fold(comp, "@scheme") {
        out.append(view.scheme);
        return true;
    }
    out.clear();
    return false;
}

fn normalize_header_value<B>(val: const u8[:], out: B&) -> bool {
    let trimmed = val.trim_lws_start().trim_end_bytes(" \t\r\n");
    guard trimmed.len > 0 else { return false; }
    var prev_space = false;
    for i in trimmed.len {
        let ch = trimmed[i];
        if ch == ' ' || ch == '\t' {
            if !prev_space {
                out.push(' ' as u8);
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    return true;
}

// Extracts component value per RFC 9421 Section 2.
//
// Example:
//   req has method "GET", comp = "@method"
//   returns: true, out populated with "GET"
fn extract_component_value(req: const Request&, comp: const u8[:], out: u8[..1024]&) -> bool {
    out.clear();
    if eq_ascii_fold(comp, "@method") {
        out.append(req.method[..]);
        return true;
    }
    if eq_ascii_fold(comp, "@target-uri") {
        out.append(req.url[..]);
        return true;
    }
    if comp.len > 0 && comp[0] == '@' {
        return extract_url_component(req.url[..], comp, out);
    }
    let val = req.header(comp);
    return normalize_header_value(val, out);
}

fn strip_req_component_suffix(comp: const u8[:]) -> const u8[:], bool {
    guard comp.len > 4 else { return comp, false; }
    let s0 = sig_sub_len(comp.len, 4);
    guard comp[s0..] == ";req" else { return comp, false; }
    return comp[..s0], true;
}

// Extracts component value from Response (RFC 9421 §2.2), supporting @status and ";req" parameters.
//
// Example:
//   res has status 200, comp = "@status"
//   returns: true, out populated with "200"
fn extract_response_component_value(
    res:  const Response&,
    req:  const Request&,
    comp: const u8[:],
    out:  u8[..1024]&,
) -> bool {
    out.clear();
    if eq_ascii_fold(comp, "@status") {
        core::format_i64_dec(res.status_code, out);
        return true;
    }
    let req_comp, is_req = strip_req_component_suffix(comp);
    if is_req {
        return extract_component_value(req, req_comp, out);
    }
    let val = res.header(comp);
    return normalize_header_value(val, out);
}

// Formats the "@signature-params" inner-list and parameters (RFC 9421 Section 2.5)
fn format_signature_params<B>(params: const HttpSignatureParams&, out: B&) {
    out.push('(' as u8);
    for idx in params.components.len {
        if idx > 0 {
            out.push(' ' as u8);
        }
        out.push('"' as u8);
        out.append(params.components[idx][..]);
        out.push('"' as u8);
    }
    out.push(')' as u8);

    if params.created > 0 {
        out.append(";created=");
        core::format_i64_dec(params.created, out);
    }
    if params.expires > 0 {
        out.append(";expires=");
        core::format_i64_dec(params.expires, out);
    }
    if params.key_id.len > 0 {
        out.append(";keyid=\"");
        out.append(params.key_id[..]);
        out.push('"' as u8);
    }
    if params.alg.len > 0 {
        out.append(";alg=\"");
        out.append(params.alg[..]);
        out.push('"' as u8);
    }
    if params.nonce.len > 0 {
        out.append(";nonce=\"");
        out.append(params.nonce[..]);
        out.push('"' as u8);
    }
}

// ---- Signature Base Generation (RFC 9421 Section 2.5) --------------------

fn build_signature_base<B>(
    req:    const Request&,
    params: const HttpSignatureParams&,
    out:    B&,
) -> bool {
    out.clear();
    for idx in params.components.len {
        let comp = params.components[idx][..];
        var val: u8[..1024] = [];
        guard extract_component_value(req, comp, val) else {
            return false;
        }
        out.push('"' as u8);
        out.append(comp);
        out.append("\": ");
        out.append(val[..]);
        out.push('\n' as u8);
    }

    out.append("\"@signature-params\": ");
    format_signature_params(params, out);
    return true;
}

fn build_response_signature_base<B>(
    res:    const Response&,
    req:    const Request&,
    params: const HttpSignatureParams&,
    out:    B&,
) -> bool {
    out.clear();
    for idx in params.components.len {
        let comp = params.components[idx][..];
        var val: u8[..1024] = [];
        guard extract_response_component_value(res, req, comp, val) else {
            return false;
        }
        out.push('"' as u8);
        out.append(comp);
        out.append("\": ");
        out.append(val[..]);
        out.push('\n' as u8);
    }

    out.append("\"@signature-params\": ");
    format_signature_params(params, out);
    return true;
}

// ---- Cryptographic Engine (HMAC-SHA256 & Ed25519) ------------------------

fn compute_signature_b64(
    alg:        const u8[:],
    secret_key: const u8[:],
    sig_base:   const u8[:],
    out:        u8[..256]&,
) -> bool {
    if alg == SIG_ALG_ED25519 {
        guard secret_key.len == 32 else { return false; }
        var seed_arr: u8[32] = [0; 32];
        for i in 32 { seed_arr[i] = secret_key[i]; }
        let ed_sig = core::ed25519_sign(seed_arr, sig_base);
        core::base64_encode(ed_sig[..], out);
        return true;
    }
    let hmac_sig = core::hmac_sha256(secret_key, sig_base);
    core::base64_encode(hmac_sig[..], out);
    return true;
}

fn verify_crypto_signature(
    alg:          const u8[:],
    key_bytes:    const u8[:],
    sig_base:     const u8[:],
    received_sig: const u8[:],
) -> bool {
    if alg == SIG_ALG_ED25519 {
        guard key_bytes.len == 32 && received_sig.len == 64 else { return false; }
        var pub_arr: u8[32] = [0; 32];
        for i in 32 { pub_arr[i] = key_bytes[i]; }
        var sig_arr: u8[64] = [0; 64];
        for i in 64 { sig_arr[i] = received_sig[i]; }
        return core::ed25519_verify(pub_arr, sig_base, sig_arr);
    }
    let expected_sig = core::hmac_sha256(key_bytes, sig_base);
    guard received_sig.len == expected_sig.len else { return false; }
    return core::ct_eq_bytes(received_sig, expected_sig[..]);
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

fn validate_signature_created(created: i64, expires: i64, now_sec: i64) -> bool {
    if created > 0 && expires > 0 {
        guard created < expires else { return false; }
    }
    if created > 0 && now_sec > 0 {
        let max_skew = sig_add_skew(now_sec);
        guard max_skew >= created else { return false; }
    }
    return true;
}

fn validate_signature_expires(expires: i64, now_sec: i64) -> bool {
    if expires > 0 && now_sec > 0 {
        let min_skew = sig_sub_skew(now_sec);
        guard min_skew <= expires else { return false; }
    }
    return true;
}

fn validate_signature_timestamps(params: const HttpSignatureParams&, now_sec: i64) -> bool {
    guard validate_signature_created(params.created, params.expires, now_sec) else { return false; }
    return validate_signature_expires(params.expires, now_sec);
}

fn format_signature_header_value(label: const u8[:], b64_sig: const u8[:], out: u8[..256]&) {
    out.clear();
    out.append(label);
    out.append("=:");
    out.append(b64_sig);
    out.push(':');
}

fn format_signature_input_header_value(params: const HttpSignatureParams&, out: u8[..1024]&) {
    out.clear();
    out.append(params.label[..]);
    out.push('=');
    format_signature_params(params, out);
}

fn attach_request_signature_headers(req: Request&, params: const HttpSignatureParams&, b64_sig: const u8[:]) {
    var input_hdr: u8[..1024] = [];
    format_signature_input_header_value(params, input_hdr);
    var sig_hdr: u8[..256] = [];
    format_signature_header_value(params.label[..], b64_sig, sig_hdr);
    set_header(req, HEADER_SIGNATURE_INPUT, input_hdr[..]);
    set_header(req, HEADER_SIGNATURE, sig_hdr[..]);
}

fn attach_response_signature_headers(res: Response&, params: const HttpSignatureParams&, b64_sig: const u8[:]) {
    var input_hdr: u8[..1024] = [];
    format_signature_input_header_value(params, input_hdr);
    var sig_hdr: u8[..256] = [];
    format_signature_header_value(params.label[..], b64_sig, sig_hdr);
    res.set_header(HEADER_SIGNATURE_INPUT, input_hdr[..]);
    res.set_header(HEADER_SIGNATURE, sig_hdr[..]);
}

// ---- Request Signing & Verification --------------------------------------

// Signs an HTTP request according to RFC 9421 and attaches Signature-Input and Signature headers.
fn sign_http_request(
    req:        Request&,
    params:     const HttpSignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var sig_base: u8[..2048] = [];
    guard build_signature_base(req, params, sig_base) else {
        return false;
    }

    var b64_sig: u8[..256] = [];
    guard compute_signature_b64(params.alg[..], secret_key, sig_base[..], b64_sig) else { return false; }

    attach_request_signature_headers(req, params, b64_sig[..]);
    return true;
}

// Verifies an RFC 9421 signature on a Request (HMAC-SHA256 or Ed25519).
fn verify_http_signature(
    req:       const Request&,
    label:     const u8[:],
    params:    const HttpSignatureParams&,
    key_bytes: const u8[:],
    now_sec:   i64 = 0,
) -> bool {
    guard validate_signature_timestamps(params, now_sec) else { return false; }

    var sig_base: u8[..2048] = [];
    guard build_signature_base(req, params, sig_base) else { return false; }

    let sig_header_val = req.header(HEADER_SIGNATURE);
    guard sig_header_val.len > 0 else { return false; }

    let received_b64, ok = extract_signature_value(sig_header_val, label);
    guard ok else { return false; }

    var received_sig: u8[..128] = [];
    guard core::base64_decode(received_b64, received_sig) else { return false; }

    return verify_crypto_signature(params.alg[..], key_bytes, sig_base[..], received_sig[..]);
}

// ---- Response Signing & Verification -------------------------------------

// Signs an HTTP response according to RFC 9421.
fn sign_http_response(
    res:        Response&,
    req:        const Request&,
    params:     const HttpSignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var sig_base: u8[..2048] = [];
    guard build_response_signature_base(res, req, params, sig_base) else {
        return false;
    }

    var b64_sig: u8[..256] = [];
    guard compute_signature_b64(params.alg[..], secret_key, sig_base[..], b64_sig) else { return false; }

    attach_response_signature_headers(res, params, b64_sig[..]);
    return true;
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
    guard validate_signature_timestamps(params, now_sec) else { return false; }

    var sig_base: u8[..2048] = [];
    guard build_response_signature_base(res, req, params, sig_base) else { return false; }

    let sig_header_val = res.header(HEADER_SIGNATURE);
    guard sig_header_val.len > 0 else { return false; }

    let received_b64, ok = extract_signature_value(sig_header_val, label);
    guard ok else { return false; }

    var received_sig: u8[..128] = [];
    guard core::base64_decode(received_b64, received_sig) else { return false; }

    return verify_crypto_signature(params.alg[..], key_bytes, sig_base[..], received_sig[..]);
}

// ---- High-Level Convenience Helpers --------------------------------------

// Signs request with RFC 9421 HTTP Message Signatures using Ed25519.
// Automatically configures standard component identifiers (@method, @authority, @path, @query).
fn sign_request_ed25519(req: Request&, key_id: const u8[:], private_key: const u8[:]) -> bool {
    var params = HttpSignatureParams { .. };
    if key_id.len > 0 {
        params.key_id.append(key_id);
    }
    params.alg.clear();
    params.alg.append(SIG_ALG_ED25519);
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
        params.key_id.append(key_id);
    }
    params.alg.clear();
    params.alg.append(SIG_ALG_ED25519);
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
        params.key_id.append(key_id);
    }
    params.alg.clear();
    params.alg.append(SIG_ALG_ED25519);
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
        params.key_id.append(key_id);
    }
    params.alg.clear();
    params.alg.append(SIG_ALG_ED25519);
    params.components.push("@status");
    params.components.push("content-type");
    return verify_http_response_signature(res, req, "sig1", params, public_key);
}
