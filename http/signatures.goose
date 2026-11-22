// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9421 HTTP Message Signatures (obsoleting all previous draft-cavage specifications).
// Provides end-to-end cryptographic signing and verification of HTTP message components
// using RFC 8941 Structured Fields formatting for Signature-Input and Signature headers.
// Supports HMAC-SHA256 and Ed25519, request and response signing, and component parameters.
namespace http;

import std;
import core;
import .request;
import .response;
import .sfv;
import http.sig_internal;

// ---- RFC 9421 Constants --------------------------------------------------

struct SignatureParams {
    label:      u8[..32]       = "sig1",
    key_id:     u8[..64]       = [],
    alg:        u8[..32]       = "hmac-sha256",
    created:    i64            = 0,
    expires:    i64            = 0,
    nonce:      u8[..64]       = [],
    components: u8[..32][..16] = [],
}

// ---- Helper Functions & Port Inspection -----------------------------------

// ---- Signature Base Generation (RFC 9421 Section 2.5) --------------------

fn build_signature_base<B>(
    req:    const Request&,
    params: const SignatureParams&,
    out:    B&,
) -> bool {
    var sp_line: u8[..2048] = [];
    guard http_internal::format_signature_params(params, sp_line) else { return false; }
    out.clear();
    return http_internal::build_signature_base_from_params_line(req, params.components, sp_line[..], out);
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
    return http_internal::compute_rsa_raw_signature(alg, secret_key, sig_base, out_sig);
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
        if key_bytes.len > 0 && key_bytes[0] == 0x30 {
            return core::rsa_pss_sha512_verify_der(key_bytes, sig_base, received_sig);
        }
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

// ---- Request Signing & Verification --------------------------------------

// Signs an HTTP request using an injected UFCS `<Signer>` (HSM / PKCS#11 / CloudKMS).
fn sign_request_with<Signer>(
    req:    Request&,
    params: const SignatureParams&,
    signer: Signer&,
) -> bool {
    guard http_internal::validate_signature_timestamps(params, 0) else { return false; }
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
    return http_internal::attach_request_signature_headers(req, params, b64_sig[..]);
}

// Signs an HTTP request according to RFC 9421 and attaches Signature-Input and Signature headers.
fn sign_request(
    req:        Request&,
    params:     const SignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var signer, ok_s = new_memory_key_signer(secret_key);
    guard ok_s else { return false; }
    defer clear_memory_key_signer(signer);
    return sign_request_with(req, params, signer);
}

fn matches_signature_component(item: const SfItem&, exp_comp: const u8[:]) -> bool {
    guard item.kind == SfType.String else { return false; }
    let base_comp, exp_has_req = http_internal::strip_req_component_suffix(exp_comp);
    guard item.str_val == base_comp else { return false; }
    var saw_req_flag = false;
    for &p in item.params {
        if p.key[..] == "req" {
            guard exp_has_req && p.kind == SfType.Boolean && p.bool_val else {
                return false;
            }
            saw_req_flag = true;
        }
    }
    return !exp_has_req || saw_req_flag;
}

fn append_wire_sf_bare<B>(
    kind:     SfType,
    int_val:  i64,
    dec_val:  f64,
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
        serialize_sfv_decimal(http_internal::sf_f64_to_milliths(dec_val), dbuf);
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

fn verify_signature_input_label(
    sig_input_val: const u8[:],
    label:         const u8[:],
    params:        const SignatureParams&,
) -> bool {
    var wire_sp: u8[..2048] = [];
    var wc:      i64        = 0;
    var we:      i64        = 0;
    return http_internal::find_verified_sig_params_line(sig_input_val, label, params, wire_sp, wc, we);
}

// Verifies an RFC 9421 signature on a Request using an injected UFCS `<Verifier>`.
fn verify_signature_with<Verifier>(
    req:      const Request&,
    label:    const u8[:],
    params:   const SignatureParams&,
    verifier: Verifier&,
    now_sec:  i64 = 0,
) -> bool {
    guard label == params.label else { return false; }
    guard http_internal::validate_signature_timestamps(params, now_sec) else { return false; }

    var wire_sig_params: u8[..2048] = [];
    var received_sig:    u8[..512]  = [];
    guard http_internal::validate_and_decode_signature_headers(
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
    guard http_internal::build_signature_base_from_params_line(
        req, params.components, wire_sig_params[..], sig_base,
    ) else {
        return false;
    }

    return verifier.verify_message(params.alg[..], sig_base[..], received_sig[..]);
}

// Verifies an RFC 9421 signature on a Request.
fn verify_signature(
    req:       const Request&,
    label:     const u8[:],
    params:    const SignatureParams&,
    key_bytes: const u8[:],
    now_sec:   i64 = 0,
) -> bool {
    var verifier, ok_v = new_memory_key_signer(key_bytes);
    guard ok_v else { return false; }
    defer clear_memory_key_signer(verifier);
    return verify_signature_with(req, label, params, verifier, now_sec);
}

// ---- Response Signing & Verification -------------------------------------

// Signs an HTTP response using an injected UFCS `<Signer>` (HSM / PKCS#11 / CloudKMS).
fn sign_response_with<Signer>(
    res:    Response&,
    req:    const Request&,
    params: const SignatureParams&,
    signer: Signer&,
) -> bool {
    guard http_internal::validate_signature_timestamps(params, 0) else { return false; }
    var sig_base: u8[..4096] = [];
    guard http_internal::build_response_signature_base(res, req, params, sig_base) else {
        return false;
    }

    var raw_sig: u8[..512] = [];
    guard signer.sign_message(params.alg[..], sig_base[..], raw_sig) else {
        return false;
    }

    var b64_sig: u8[..1024] = [];
    core::base64_encode(raw_sig[..], b64_sig);
    return http_internal::attach_response_signature_headers(res, params, b64_sig[..]);
}

// Signs an HTTP response according to RFC 9421.
fn sign_response(
    res:        Response&,
    req:        const Request&,
    params:     const SignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var signer, ok_s = new_memory_key_signer(secret_key);
    guard ok_s else { return false; }
    defer clear_memory_key_signer(signer);
    return sign_response_with(res, req, params, signer);
}

// Verifies an RFC 9421 signature on a Response using an injected UFCS `<Verifier>`.
fn verify_response_signature_with<Verifier>(
    res:      const Response&,
    req:      const Request&,
    label:    const u8[:],
    params:   const SignatureParams&,
    verifier: Verifier&,
    now_sec:  i64 = 0,
) -> bool {
    guard label == params.label else { return false; }
    guard http_internal::validate_signature_timestamps(params, now_sec) else { return false; }

    var wire_sig_params: u8[..2048] = [];
    var received_sig:    u8[..512]  = [];
    guard http_internal::validate_and_decode_signature_headers(
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
    guard http_internal::build_response_signature_base_from_params_line(
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
fn verify_response_signature(
    res:       const Response&,
    req:       const Request&,
    label:     const u8[:],
    params:    const SignatureParams&,
    key_bytes: const u8[:],
    now_sec:   i64 = 0,
) -> bool {
    var verifier, ok_v = new_memory_key_signer(key_bytes);
    guard ok_v else { return false; }
    defer clear_memory_key_signer(verifier);
    return verify_response_signature_with(res, req, label, params, verifier, now_sec);
}

// ---- High-Level Convenience Helpers --------------------------------------

// Signs request with RFC 9421 HTTP Message Signatures using Ed25519.
// Automatically configures standard component identifiers (@method, @authority, @path, @query).
fn sign_request_ed25519(req: Request&, key_id: const u8[:], private_key: const u8[:]) -> bool {
    var params = SignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@method");
    params.components.push("@authority");
    params.components.push("@path");
    params.components.push("@query");
    return sign_request(req, params, private_key);
}

// Verifies request signature using Ed25519 public key and key_id.
fn verify_request_ed25519(req: const Request&, key_id: const u8[:], public_key: const u8[:]) -> bool {
    var params = SignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@method");
    params.components.push("@authority");
    params.components.push("@path");
    params.components.push("@query");
    return verify_signature(req, "sig1", params, public_key);
}

// Signs response with RFC 9421 HTTP Message Signatures using Ed25519.
// Automatically configures standard component identifiers (@status, content-type).
fn sign_response_ed25519(
    res:         Response&,
    req:         const Request&,
    key_id:      const u8[:],
    private_key: const u8[:],
) -> bool {
    var params = SignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@status");
    params.components.push("content-type");
    return sign_response(res, req, params, private_key);
}

// Verifies response signature using Ed25519 public key and key_id.
fn verify_response_ed25519(
    res:        const Response&,
    req:        const Request&,
    key_id:     const u8[:],
    public_key: const u8[:],
) -> bool {
    var params = SignatureParams { .. };
    if key_id.len > 0 {
        guard params.key_id.try_set(key_id) else { return false; }
    }
    let _ = params.alg.try_set(rfc::SIG_ALG_ED25519);
    params.components.push("@status");
    params.components.push("content-type");
    return verify_response_signature(res, req, "sig1", params, public_key);
}
