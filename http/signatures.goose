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

// Extracts special URL components (@authority, @path, @query, @scheme) per RFC 9421 §2.2.6.
//
// Example:
//   url_str = "https://example.com/foo?bar=1", comp = "@authority"
//   returns: true, out populated with "example.com"
fn extract_url_component(url_str: const u8[:], comp: const u8[:], out: u8[..1024]&) -> bool {
    let view, err = core::parse_url_view(url_str);
    guard view.valid else {
        out.clear();
        return false;
    }
    if comp.eq_ascii_fold("@authority") {
        guard view.host.len + 8 <= out.cap else {
            out.clear();
            return false;
        }
        out.clear();
        out.append(view.host);
        to_lower(out[..]);
        if view.port > 0 && !is_default_port(view.scheme, view.port) {
            out.push(':');
            view.port.format_i64_dec(out);
        }
        return true;
    }
    if comp.eq_ascii_fold("@path") {
        let p = if view.pathname.len > 0 { view.pathname } else { "/" };
        guard out.try_set(p) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp.eq_ascii_fold("@query") {
        let q = if view.search.len > 0 { view.search } else { "?" };
        guard out.try_set(q) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp.eq_ascii_fold("@request-target") {
        let p = if view.pathname.len > 0 { view.pathname } else { "/" };
        guard p.len + view.search.len <= out.cap else {
            out.clear();
            return false;
        }
        out.clear();
        out.append(p);
        if view.search.len > 0 {
            out.append(view.search);
        }
        return true;
    }
    if comp.eq_ascii_fold("@scheme") {
        guard out.try_set(view.scheme) else {
            out.clear();
            return false;
        }
        to_lower(out[..]);
        return true;
    }
    out.clear();
    return false;
}

fn normalize_header_value<B>(val: const u8[:], out: B&) -> bool {
    let trimmed = val.trim_lws_start().trim_end_bytes(" \t\r\n");
    if trimmed.len == 0 {
        return true;
    }
    var prev_space = false;
    for i in trimmed.len {
        let ch = trimmed[i];
        let is_ws = ch == ' ' || ch == '\t';
        if is_ws && prev_space {
            continue;
        }
        guard out.try_push(if is_ws { ' ' as u8 } else { ch }) else {
            out.clear();
            return false;
        }
        prev_space = is_ws;
    }
    return true;
}

// Extracts and concatenates comma-separated header field values (RFC 9421 §2.1).
//
// Example:
//   headers = [{"date", "Tue, 20 Apr 2021"}], name = "date"
//   returns: true, out = "Tue, 20 Apr 2021"
fn extract_combined_header_value<B>(headers: const HeaderMap&, name: const u8[:], out: B&) -> bool {
    var found = false;
    for &e in headers.entries {
        guard entry_name(headers, e).eq_ascii_fold(name) else { continue; }
        var norm_buf: u8[..1024] = [];
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
fn extract_component_value(req: const Request&, comp: const u8[:], out: u8[..1024]&) -> bool {
    if comp.eq_ascii_fold("@method") {
        let _ = out.try_set(req.method[..]);
        return true;
    }
    if comp.eq_ascii_fold("@target-uri") {
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
fn extract_response_component_value(
    res:  const Response&,
    req:  const Request&,
    comp: const u8[:],
    out:  u8[..1024]&,
) -> bool {
    out.clear();
    if comp.eq_ascii_fold("@status") {
        res.status_code.format_i64_dec(out);
        return true;
    }
    let req_comp, is_req = strip_req_component_suffix(comp);
    if is_req {
        return extract_component_value(req, req_comp, out);
    }
    return extract_combined_header_value(res.headers, comp, out);
}

fn append_escaped_string_param<B>(s: const u8[:], out: B&) {
    for b in s {
        if b == '"' || b == '\\' {
            out.push('\\' as u8);
        }
        out.push(b);
    }
}

// Formats the "@signature-params" inner-list and parameters (RFC 9421 Section 2.5)
fn format_signature_params<B>(params: const HttpSignatureParams&, out: B&) {
    out.push('(' as u8);
    for idx in params.components.len {
        if idx > 0 {
            out.push(' ' as u8);
        }
        let base_comp, has_req = strip_req_component_suffix(params.components[idx][..]);
        out.push('"' as u8);
        out.append(base_comp);
        out.push('"' as u8);
        if has_req {
            out.append(";req");
        }
    }
    out.push(')' as u8);

    if params.created > 0 {
        out.append(";created=");
        params.created.format_i64_dec(out);
    }
    if params.expires > 0 {
        out.append(";expires=");
        params.expires.format_i64_dec(out);
    }
    if params.key_id.len > 0 {
        out.append(";keyid=\"");
        append_escaped_string_param(params.key_id[..], out);
        out.push('"' as u8);
    }
    if params.alg.len > 0 {
        out.append(";alg=\"");
        append_escaped_string_param(params.alg[..], out);
        out.push('"' as u8);
    }
    if params.nonce.len > 0 {
        out.append(";nonce=\"");
        append_escaped_string_param(params.nonce[..], out);
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
        let base_comp, has_req = strip_req_component_suffix(comp);
        out.push('"' as u8);
        out.append(base_comp);
        out.push('"' as u8);
        if has_req {
            out.append(";req");
        }
        out.append(": ");
        out.append(val[..]);
        out.push('\n' as u8);
    }

    out.append("\"@signature-params\": ");
    format_signature_params(params, out);
    return true;
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
        return core::ecdsa_p256_verify(key_bytes, sig_base, received_sig);
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

fn validate_signature_created(created: i64, expires: i64, now_sec: i64) -> bool {
    if created > 0 && expires > 0 {
        guard created < expires else { return false; }
    }
    if created > 0 && now_sec > 0 {
        let max_skew = now_sec + 60;
        guard max_skew >= created else { return false; }
    }
    return true;
}

fn validate_signature_expires(expires: i64, now_sec: i64) -> bool {
    if expires > 0 && now_sec > 0 {
        let min_skew = now_sec - 60;
        guard min_skew <= expires else { return false; }
    }
    return true;
}

fn validate_signature_timestamps(params: const HttpSignatureParams&, now_sec: i64) -> bool {
    guard validate_signature_created(params.created, params.expires, now_sec) else { return false; }
    return validate_signature_expires(params.expires, now_sec);
}

fn format_signature_header_value(label: const u8[:], b64_sig: const u8[:], out: u8[..1024]&) {
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
    var sig_hdr: u8[..1024] = [];
    format_signature_header_value(params.label[..], b64_sig, sig_hdr);
    set_header(req, rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    set_header(req, rfc::HEADER_SIGNATURE, sig_hdr[..]);
}

fn attach_response_signature_headers(res: Response&, params: const HttpSignatureParams&, b64_sig: const u8[:]) {
    var input_hdr: u8[..1024] = [];
    format_signature_input_header_value(params, input_hdr);
    var sig_hdr: u8[..1024] = [];
    format_signature_header_value(params.label[..], b64_sig, sig_hdr);
    res.set_header(rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    res.set_header(rfc::HEADER_SIGNATURE, sig_hdr[..]);
}

// ---- Request Signing & Verification --------------------------------------

// Signs an HTTP request using an injected UFCS `<Signer>` (HSM / PKCS#11 / CloudKMS).
fn sign_http_request_with<Signer>(
    req:    Request&,
    params: const HttpSignatureParams&,
    signer: Signer&,
) -> bool {
    var sig_base: u8[..2048] = [];
    guard build_signature_base(req, params, sig_base) else {
        return false;
    }

    var raw_sig: u8[..512] = [];
    guard signer.sign_message(params.alg[..], sig_base[..], raw_sig) else {
        return false;
    }

    var b64_sig: u8[..1024] = [];
    core::base64_encode(raw_sig[..], b64_sig);
    attach_request_signature_headers(req, params, b64_sig[..]);
    return true;
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

fn verify_signature_input_label(
    sig_input_val: const u8[:],
    label:         const u8[:],
    params:        const HttpSignatureParams&,
) -> bool {
    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(sig_input_val, entries) else { return false; }
    for &entry in entries {
        guard entry.key == label && entry.is_inner_list else { continue; }
        guard entry.inner_items.len == params.components.len else { return false; }
        for i in params.components.len {
            guard matches_signature_component(entry.inner_items[i], params.components[i][..]) else {
                return false;
            }
        }
        for &p in entry.params {
            if p.key == "alg" {
                guard p.item.kind == SfType.String && p.item.str_val == params.alg[..] else { return false; }
            } else if p.key == "keyid" {
                guard p.item.kind == SfType.String && p.item.str_val == params.key_id[..] else { return false; }
            } else if p.key == "created" {
                guard p.item.kind == SfType.Integer && p.item.int_val == params.created else { return false; }
            } else if p.key == "expires" {
                guard p.item.kind == SfType.Integer && p.item.int_val == params.expires else { return false; }
            } else if p.key == "nonce" {
                guard p.item.kind == SfType.String && p.item.str_val == params.nonce[..] else { return false; }
            }
        }
        return true;
    }
    return false;
}

fn validate_and_decode_signature_headers(
    headers: const HeaderMap&,
    label:   const u8[:],
    params:  const HttpSignatureParams&,
    out_sig: u8[..512]&,
) -> bool {
    out_sig.clear();
    var comb_in: u8[..1024] = [];
    let ok_in = headers.get_combined(rfc::HEADER_SIGNATURE_INPUT, comb_in, 1024);
    let sig_input_val = if ok_in { comb_in[..] } else { headers.get_header(rfc::HEADER_SIGNATURE_INPUT) };
    guard sig_input_val.len > 0 && verify_signature_input_label(sig_input_val, label, params) else {
        return false;
    }

    var comb_sig: u8[..1024] = [];
    let ok_sig = headers.get_combined(rfc::HEADER_SIGNATURE, comb_sig, 1024);
    let sig_header_val = if ok_sig { comb_sig[..] } else { headers.get_header(rfc::HEADER_SIGNATURE) };
    guard sig_header_val.len > 0 else { return false; }

    let received_b64, ok = extract_signature_value(sig_header_val, label);
    guard ok else { return false; }

    guard core::base64_decode(received_b64, out_sig) else {
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

    var sig_base: u8[..2048] = [];
    guard build_signature_base(req, params, sig_base) else { return false; }

    var received_sig: u8[..512] = [];
    guard validate_and_decode_signature_headers(req.headers, label, params, received_sig) else {
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
    var sig_base: u8[..2048] = [];
    guard build_response_signature_base(res, req, params, sig_base) else {
        return false;
    }

    var raw_sig: u8[..512] = [];
    guard signer.sign_message(params.alg[..], sig_base[..], raw_sig) else {
        return false;
    }

    var b64_sig: u8[..1024] = [];
    core::base64_encode(raw_sig[..], b64_sig);
    attach_response_signature_headers(res, params, b64_sig[..]);
    return true;
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

    var sig_base: u8[..2048] = [];
    guard build_response_signature_base(res, req, params, sig_base) else { return false; }

    var received_sig: u8[..512] = [];
    guard validate_and_decode_signature_headers(res.headers, label, params, received_sig) else {
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
