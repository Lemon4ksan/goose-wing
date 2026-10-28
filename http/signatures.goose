// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9421 HTTP Message Signatures (obsoleting all previous draft-cavage specifications).
// Provides end-to-end cryptographic signing and verification of HTTP message components
// using RFC 8941 Structured Fields formatting for Signature-Input and Signature headers.
namespace wing;

import std;
import core from "..";
import client.request;
import client.response;

// ---- 1. RFC 9421 Constants --------------------------------------------------

const HEADER_SIGNATURE_INPUT: const u8[:] = "Signature-Input";
const HEADER_SIGNATURE: const u8[:] = "Signature";

const SIG_ALG_HMAC_SHA256: const u8[:] = "hmac-sha256";
const SIG_ALG_ED25519: const u8[:] = "ed25519";

// ---- 2. Signature Models ----------------------------------------------------

struct HttpSignatureParams {
    label: u8[..32] = "sig1",
    key_id: u8[..64] = [],
    alg: u8[..32] = "hmac-sha256",
    created: i64 = 0,
    expires: i64 = 0,
    nonce: u8[..64] = [],
    components: u8[..32][..16] = [],
}

// ---- 3. Component Extraction Helpers ---------------------------------------

// Extracts component value per RFC 9421 Section 2
fn extract_component_value<B>(req: const Request&, comp: const u8[:], out: B&) -> bool {
    out.clear();
    if eq_ascii_fold(comp, "@method") {
        out.append(req.method[..]);
        return true;
    } else if eq_ascii_fold(comp, "@target-uri") {
        out.append(req.url[..]);
        return true;
    } else if eq_ascii_fold(comp, "@authority") {
        // Extract host[:port] from URL
        let url = req.url[..];
        var start = 0;
        for i in url.len - 2 {
            if url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/' {
                start = i + 3;
                break;
            }
        }
        var end = url.len;
        for i in (url.len - start) {
            let ch = url[start + i];
            if ch == '/' || ch == '?' || ch == '#' {
                end = start + i;
                break;
            }
        }
        out.append(url[start..end]);
        return true;
    } else if eq_ascii_fold(comp, "@scheme") {
        let url = req.url[..];
        for i in url.len {
            if url[i] == ':' {
                out.append(url[..i]);
                return true;
            }
        }
        out.append("https");
        return true;
    } else if eq_ascii_fold(comp, "@path") {
        let url = req.url[..];
        var path_start = -1;
        var slashes = 0;
        for i in url.len {
            if url[i] == '/' {
                slashes += 1;
                if slashes == 3 {
                    path_start = i;
                    break;
                }
            }
        }
        if path_start == -1 {
            out.append("/");
            return true;
        }
        var path_end = url.len;
        for i in (url.len - path_start) {
            let ch = url[path_start + i];
            if ch == '?' || ch == '#' {
                path_end = path_start + i;
                break;
            }
        }
        out.append(url[path_start..path_end]);
        return true;
    } else if eq_ascii_fold(comp, "@query") {
        // RFC 9421 Section 2.2.7: Query component beginning with '?'
        let url = req.url[..];
        var q_start = -1;
        for i in url.len {
            if url[i] == '?' {
                q_start = i;
                break;
            }
        }
        if q_start == -1 {
            out.append("?");
            return true;
        }
        var q_end = url.len;
        for i in (url.len - q_start) {
            if url[q_start + i] == '#' {
                q_end = q_start + i;
                break;
            }
        }
        out.append(url[q_start..q_end]);
        return true;
    } else if comp.len > 0 && comp[0] != '@' {
        // Standard HTTP header field (RFC 9421 Section 2.1)
        // Values must be stripped of leading/trailing whitespace and internal whitespace collapsed.
        let val = req.header(comp);
        guard val.len > 0 else { return false; }
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

    return false;
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

// ---- 4. Signature Base Generation (RFC 9421 Section 2.5) --------------------

// Builds the canonical signature base string:
// "<component-identifier>": <component-value>\n
// ...
// "@signature-params": <signature-params>
fn build_signature_base<B>(
    req: const Request&,
    params: const HttpSignatureParams&,
    out: B&,
) -> bool {
    out.clear();
    for idx in params.components.len {
        let comp = params.components[idx][..];
        var val: u8[..1024] = [];
        guard extract_component_value(req, comp, val) else {
            return false;
        }

        // Canonical line: "comp": val\n
        out.push('"' as u8);
        out.append(comp);
        out.append("\": ");
        out.append(val[..]);
        out.push('\n' as u8);
    }

    // Final line: "@signature-params": <signature-params> (no trailing newline)
    out.append("\"@signature-params\": ");
    format_signature_params(params, out);

    return true;
}

// ---- 5. Request Signing & Verification --------------------------------------

// Signs an HTTP request according to RFC 9421 and attaches Signature-Input and Signature headers.
fn sign_http_request(
    req: Request&,
    params: const HttpSignatureParams&,
    secret_key: const u8[:],
) -> bool {
    var sig_base: u8[>..] = [];
    guard build_signature_base(req, params, sig_base) else {
        return false;
    }

    // Compute HMAC-SHA256 signature
    let sig_raw = core::hmac_sha256(secret_key, sig_base[..]);

    // Format Signature-Input header: <label>=<signature-params>
    var input_hdr: u8[..1024] = [];
    input_hdr.append(params.label[..]);
    input_hdr.push('=');
    format_signature_params(params, input_hdr);

    // Format Signature header (RFC 8941 sf-binary :<base64>:): <label>=:<base64>:
    var sig_hdr: u8[..256] = [];
    sig_hdr.append(params.label[..]);
    sig_hdr.append("=:");
    core::base64_encode(sig_raw[..], sig_hdr);
    sig_hdr.push(':');

    set_header(req, HEADER_SIGNATURE_INPUT, input_hdr[..]);
    set_header(req, HEADER_SIGNATURE, sig_hdr[..]);

    return true;
}

// Parses an RFC 8941 Structured Fields Dictionary for Signature header
// and extracts the sf-binary (:base64:) corresponding to the given label.
fn extract_signature_value(header_val: const u8[:], label: const u8[:]) -> const u8[:], bool {
    var idx: i64 = 0;
    while idx < header_val.len {
        let rem = header_val[idx..].trim_start_bytes(" \t,");
        idx = header_val.len - rem.len;
        guard idx < header_val.len else { break; }

        let rem_k = header_val[idx..];
        var k_len: i64 = 0;
        while k_len < rem_k.len && rem_k[k_len] != '=' && rem_k[k_len] != ' ' && rem_k[k_len] != '\t' {
            k_len += 1;
        }
        let item_key = rem_k[..k_len];
        idx += k_len;

        let rem_eq = header_val[idx..].trim_start_bytes(" \t");
        idx = header_val.len - rem_eq.len;
        guard idx < header_val.len && header_val[idx] == '=' else { return "", false; }
        idx += 1; // skip '='

        let rem_colon = header_val[idx..].trim_start_bytes(" \t");
        idx = header_val.len - rem_colon.len;
        guard idx < header_val.len && header_val[idx] == ':' else { return "", false; }
        idx += 1; // skip opening ':'

        let b64_start = idx;
        while idx < header_val.len && header_val[idx] != ':' {
            idx += 1;
        }
        guard idx < header_val.len && header_val[idx] == ':' else { return "", false; }
        let b64_val = header_val[b64_start..idx];
        idx += 1; // skip closing ':'

        if item_key == label {
            return b64_val, true;
        }
    }
    return "", false;
}

// Verifies an RFC 9421 signature on a Request using HMAC-SHA256
fn verify_http_signature(
    req: const Request&,
    label: const u8[:],
    params: const HttpSignatureParams&,
    secret_key: const u8[:],
    now_sec: i64 = 0,
) -> bool {
    // 1. RFC 9421 Section 3.2.1: Timestamp & expiration checks
    if params.created > 0 && params.expires > 0 {
        guard params.created < params.expires else { return false; }
    }
    if params.created > 0 && now_sec > 0 {
        guard (now_sec + 60) >= params.created else { return false; }
    }
    if params.expires > 0 && now_sec > 0 {
        guard (now_sec - 60) <= params.expires else { return false; }
    }

    // 2. Rebuild canonical signature base
    var sig_base: u8[>..] = [];
    guard build_signature_base(req, params, sig_base) else {
        return false;
    }

    // 3. Compute expected signature
    let expected_sig = core::hmac_sha256(secret_key, sig_base[..]);

    // 4. Find Signature header matching label and compare in constant-time
    let sig_header_val = req.header(HEADER_SIGNATURE);
    guard sig_header_val.len > 0 else { return false; }

    let received_b64, ok = extract_signature_value(sig_header_val, label);
    guard ok else { return false; }

    var received_sig: u8[>..] = [];
    guard core::base64_decode(received_b64, received_sig) else { return false; }
    guard received_sig.len == expected_sig.len else { return false; }

    return core::ct_eq_bytes(received_sig[..], expected_sig[..]);
}
