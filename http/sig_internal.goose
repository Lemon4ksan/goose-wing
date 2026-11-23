// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/sig_internal.goose).
namespace http_internal;

import std;
import core;
import http.headers;
import http.request;
import http.response;
import http.sfv;
import http.signatures;

// ---- http/signatures.goose internal helpers ----

fn is_default_port(scheme: const u8[:], port: i32) -> bool {
    if port <= 0 { return true; }
    if scheme.eq_ascii_fold("http") && port == 80 { return true; }
    if scheme.eq_ascii_fold("https") && port == 443 { return true; }
    if scheme.eq_ascii_fold("ws") && port == 80 { return true; }
    if scheme.eq_ascii_fold("wss") && port == 443 { return true; }
    return false;
}

inline fn is_valid_derived_sig_component(name: const u8[:]) -> bool {
    return name == "@method" ||
        name == "@target-uri" ||
        name == "@authority" ||
        name == "@scheme" ||
        name == "@request-target" ||
        name == "@path" ||
        name == "@query" ||
        name == "@query-param" ||
        name == "@status";
}

// RFC 9421 Section 2.1: HTTP Fields - Component names MUST be lowercase tchar or valid derived identifiers.
fn is_valid_component_name(comp: const u8[:]) -> bool {
    let base, _ = strip_req_component_suffix(comp);
    guard base.len > 0 && base != "@signature-params" else {
        return false;
    }
    if base[0] == '@' {
        return is_valid_derived_sig_component(base);
    }
    for b in base {
        guard core::is_tchar(b) && !(b >= 'A' && b <= 'Z') else {
            return false;
        }
    }
    return true;
}

inline fn has_nonzero_bytes(buf: const u8[:]) -> bool {
    var acc: u8 = 0;
    for b in buf {
        acc |= b;
    }
    return acc != 0;
}

inline fn is_valid_rsa_modulus_2048(n_be: const u8[:]) -> bool {
    return n_be.len >= 256 && n_be.len <= 512 && (n_be[0] & 0x80) != 0;
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

fn format_url_authority<B>(view: const core::UrlView&, out: B&) -> bool {
    guard out.try_append(view.host) else { return false; }
    to_lower(out[..]);
    if view.port > 0 && !is_default_port(view.scheme, view.port) {
        var pbuf: u8[..16] = [];
        view.port.format_i64_dec(pbuf);
        guard out.try_push(':') && out.try_append(pbuf[..]) else { return false; }
    }
    return true;
}

fn format_url_request_target<B>(view: const core::UrlView&, out: B&) -> bool {
    let p = if view.pathname.len > 0 { view.pathname } else { "/" };
    return out.try_append(p) && (view.search.len == 0 || out.try_append(view.search));
}

fn format_url_scheme<B>(view: const core::UrlView&, out: B&) -> bool {
    guard out.try_set(view.scheme) else { return false; }
    to_lower(out[..]);
    return true;
}

// Extracts special URL components (@authority, @path, @query, @scheme) per RFC 9421 §2.2.6.
//
// Example:
//   url_str = "https://example.com/foo?bar=1", comp = "@authority"
//   returns: true, out populated with "example.com"
fn extract_url_component<B>(url_str: const u8[:], comp: const u8[:], out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    guard is_valid_component_name(comp) else { return false; }
    let view, err = core::parse_url_view(url_str);
    let _ = err;
    guard view.valid else { return false; }
    if comp == "@authority" {
        committed = format_url_authority(view, out);
        return committed;
    }
    if comp == "@path" {
        committed = out.try_set(if view.pathname.len > 0 { view.pathname } else { "/" });
        return committed;
    }
    if comp == "@query" {
        committed = out.try_set(if view.search.len > 0 { view.search } else { "?" });
        return committed;
    }
    if comp == "@request-target" {
        committed = format_url_request_target(view, out);
        return committed;
    }
    if comp == "@scheme" {
        committed = format_url_scheme(view, out);
        return committed;
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
    // RFC 9421 Section 2.1: Strip only OWS (SP/HTAB); trailing bare CR/LF MUST fail closed.
    let trimmed = val.trim_lws();
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
fn extract_combined_header_value<B>(headers: const http::HeaderMap&, name: const u8[:], out: B&) -> bool {
    guard is_valid_component_name(name) else {
        out.clear();
        return false;
    }
    var found = false;
    for &e in headers.entries {
        guard http::entry_name(headers, e).eq_ascii_fold(name) else { continue; }
        var norm_buf: u8[..4096] = [];
        guard normalize_header_value(http::entry_value(headers, e), norm_buf) else {
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
fn extract_component_value<B>(req: const http::Request&, comp: const u8[:], out: B&) -> bool {
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
    res:  const http::Response&,
    req:  const http::Request&,
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
        guard core::is_ascii_printable(b) else { return false; }
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

fn append_signature_meta_params<B>(params: const http::SignatureParams&, out: B&) -> bool {
    if params.created > 0 && !append_named_sig_int_param("created", params.created, out) { return false; }
    if params.expires > 0 && !append_named_sig_int_param("expires", params.expires, out) { return false; }
    if params.key_id.len > 0 && !append_named_sig_str_param("keyid", params.key_id[..], out) { return false; }
    if params.alg.len > 0 && !append_named_sig_str_param("alg", params.alg[..], out) { return false; }
    if params.nonce.len > 0 && !append_named_sig_str_param("nonce", params.nonce[..], out) { return false; }
    return true;
}

// Formats the "@signature-params" inner-list and parameters (RFC 9421 Section 2.5)
fn format_signature_params<B>(params: const http::SignatureParams&, out: B&) -> bool {
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
    guard out.try_push(')' as u8) && append_signature_meta_params(params, out) else { return false; }
    committed = true;
    return true;
}

fn build_signature_base_from_params_line<B>(
    req:             const http::Request&,
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

fn build_response_signature_base_from_params_line<B>(
    res:             const http::Response&,
    req:             const http::Request&,
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
    res:    const http::Response&,
    req:    const http::Request&,
    params: const http::SignatureParams&,
    out:    B&,
) -> bool {
    out.clear();
    var sp_line: u8[..2048] = [];
    guard format_signature_params(params, sp_line) else { return false; }
    return build_response_signature_base_from_params_line(res, req, params.components, sp_line[..], out);
}

fn compute_rsa_raw_signature(
    alg:        const u8[:],
    secret_key: const u8[:],
    sig_base:   const u8[:],
    out_sig:    u8[..512]&,
) -> bool {
    out_sig.clear();
    let klen = secret_key.len;
    guard klen >= 512 && (klen & 1) == 0 else { return false; }
    let half = klen >> 1;
    guard is_valid_rsa_modulus_2048(secret_key[..half]) else { return false; }
    if alg == rfc::SIG_ALG_RSA_V1_5_SHA256 {
        guard core::rsa_pkcs1_sha256_sign(secret_key[..half], secret_key[half..], sig_base, out_sig) else {
            out_sig.clear();
            return false;
        }
        return true;
    }
    if alg == rfc::SIG_ALG_RSA_PSS_SHA512 {
        // RFC 9421 Section 3.3.1 & RFC 8017 Section 9.1.1: 64-byte random PSS salt from CSPRNG.
        var salt64: u8[64] = [0; 64];
        defer core::secure_zeroize_64(salt64);
        let got_rng = if core::sim_rng_is_active() {
            core::sim_rng_fill(salt64[..])
        } else {
            core::csprng_fill(salt64[..])
        };
        guard got_rng else { return false; }
        guard core::rsa_pss_sha512_sign(secret_key[..half], secret_key[half..], salt64[..], sig_base, out_sig) else {
            out_sig.clear();
            return false;
        }
        return true;
    }
    return false;
}

struct SigWireTimestamps {
    created:     i64  = 0,
    expires:     i64  = 0,
    has_created: bool = false,
    has_expires: bool = false,
}

inline fn resolve_sig_verify_now_sec(now_sec: i64) -> i64 {
    if now_sec > 0 { return now_sec; }
    if now_sec < 0 { return -1; }
    return core::now().wall_sec;
}

// Structural timestamp sanity check used at signing time (no wall-clock enforcement).
fn validate_sign_params_timestamps(params: const http::SignatureParams&) -> bool {
    guard params.created >= 0 && params.expires >= 0 else { return false; }
    if params.created > 0 && params.expires > 0 {
        guard params.created < params.expires else { return false; }
    }
    return true;
}

// RFC 9421 Section 2.3: Signature Parameters - Enforce created/expires bounds including wire expires=0 (AUTH-07).
fn validate_wire_signature_timestamps(ts: const SigWireTimestamps&, now_sec: i64) -> bool {
    guard ts.created >= 0 && ts.expires >= 0 else { return false; }
    if ts.has_created && ts.has_expires {
        guard ts.created < ts.expires else { return false; }
    }
    if !ts.has_created && !ts.has_expires {
        return true;
    }
    let eff_now = resolve_sig_verify_now_sec(now_sec);
    guard eff_now > 0 else { return false; }
    if ts.has_created {
        guard core::add_sat_i64(eff_now, 60) >= ts.created else { return false; }
    }
    if ts.has_expires {
        guard core::sub_sat_i64(eff_now, 60) <= ts.expires else { return false; }
    }
    return true;
}

fn validate_signature_timestamps(params: const http::SignatureParams&, now_sec: i64) -> bool {
    guard validate_sign_params_timestamps(params) else { return false; }
    let ts = SigWireTimestamps {
        created:     params.created,
        expires:     params.expires,
        has_created: params.created > 0,
        has_expires: params.expires > 0,
    };
    return validate_wire_signature_timestamps(ts, now_sec);
}

fn format_signature_header_value<B>(label: const u8[:], b64_sig: const u8[:], out: B&) -> bool {
    out.clear();
    guard out.try_append(label) && out.try_append("=:") && out.try_append(b64_sig) && out.try_push(':') else {
        out.clear();
        return false;
    }
    return true;
}

fn format_signature_input_header_value<B>(params: const http::SignatureParams&, out: B&) -> bool {
    out.clear();
    guard out.try_append(params.label[..]) && out.try_push('=') && format_signature_params(params, out) else {
        out.clear();
        return false;
    }
    return true;
}

fn attach_request_signature_headers(
    req:     http::Request&,
    params:  const http::SignatureParams&,
    b64_sig: const u8[:],
) -> bool {
    var input_hdr: u8[..4096] = [];
    var sig_hdr:   u8[..4096] = [];
    guard format_signature_input_header_value(params, input_hdr) &&
          format_signature_header_value(params.label[..], b64_sig, sig_hdr) else {
        return false;
    }
    http::set_header(req, rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    http::set_header(req, rfc::HEADER_SIGNATURE, sig_hdr[..]);
    return true;
}

fn attach_response_signature_headers(
    res:     http::Response&,
    params:  const http::SignatureParams&,
    b64_sig: const u8[:],
) -> bool {
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

inline fn sf_f64_to_milliths(d: f64) -> i64 {
    let scaled = d * 1000.0;
    let adjusted = if scaled >= 0.0 { scaled + 0.5 } else { scaled - 0.5 };
    return adjusted as i64;
}

fn append_wire_item_params<B>(params: const http::SfItemParam[:], out: B&) -> bool {
    for &p in params {
        guard out.try_push(';' as u8) && out.try_append(p.key[..]) else { return false; }
        if p.kind == http::SfType.Boolean && p.bool_val {
            continue;
        }
        guard out.try_push('=' as u8) &&
              http::append_wire_sf_bare(p.kind, p.int_val, p.dec_val, p.str_val[..], p.bool_val, out) else {
            return false;
        }
    }
    return true;
}

fn append_wire_dict_params<B>(params: const http::SfParameter[:], out: B&) -> bool {
    for &p in params {
        guard out.try_push(';' as u8) && out.try_append(p.key) else { return false; }
        if p.item.kind == http::SfType.Boolean && p.item.bool_val {
            continue;
        }
        guard out.try_push('=' as u8) &&
              http::append_wire_sf_bare(
                  p.item.kind, p.item.int_val, p.item.dec_val, p.item.str_val, p.item.bool_val, out,
              ) else {
                  return false;
              }
    }
    return true;
}

fn serialize_wire_sig_params<B>(entry: const http::SfDictEntry&, out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    guard out.try_push('(' as u8) else { return false; }
    for idx in entry.inner_items.len {
        if idx > 0 && !out.try_push(' ' as u8) { return false; }
        let it = &entry.inner_items[idx];
        guard http::append_wire_sf_bare(it.kind, it.int_val, it.dec_val, it.str_val, it.bool_val, out) &&
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

inline fn sf_str_param_matches(item: const http::SfItem&, expected: const u8[:]) -> bool {
    var unq: u8[..128] = [];
    return item.kind == http::SfType.String && http::sf_unescape_string(item.str_val, unq) && unq[..] == expected;
}

fn check_sig_entry_param(
    p:         const http::SfParameter&,
    params:    const http::SignatureParams&,
    seen_mask: u32&,
    wire_ts:   SigWireTimestamps&,
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
        guard p.item.kind == http::SfType.Integer && p.item.int_val >= 0 &&
              (params.created == 0 || p.item.int_val == params.created) else {
            return false;
        }
        wire_ts.created = p.item.int_val;
        wire_ts.has_created = true;
        seen_mask = seen_mask | 2;
        return true;
    }
    if p.key == "expires" {
        guard p.item.kind == http::SfType.Integer && p.item.int_val >= 0 &&
              (params.expires == 0 || p.item.int_val == params.expires) else {
            return false;
        }
        wire_ts.expires = p.item.int_val;
        wire_ts.has_expires = true;
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
    entry:   const http::SfDictEntry&,
    params:  const http::SignatureParams&,
    wire_ts: SigWireTimestamps&,
) -> bool {
    guard entry.inner_items.len == params.components.len else { return false; }
    for i in params.components.len {
        guard http::matches_signature_component(entry.inner_items[i], params.components[i][..]) else {
            return false;
        }
    }
    var seen_mask: u32 = 0;
    for &p in entry.params {
        guard check_sig_entry_param(p, params, seen_mask, wire_ts) else {
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
    params:         const http::SignatureParams&,
    out_sig_params: B&,
    out_ts:         SigWireTimestamps&,
) -> bool {
    out_sig_params.clear();
    out_ts = SigWireTimestamps { .. };
    guard params.created >= 0 && params.expires >= 0 && has_valid_unique_components(params.components) else {
        return false;
    }
    var entries: http::SfDictEntry[..16] = [];
    guard http::parse_sf_dict(sig_input_val, entries) else { return false; }
    for &entry in entries {
        guard entry.key == label && entry.is_inner_list else { continue; }
        var wt = SigWireTimestamps { .. };
        guard verify_sig_entry_match(entry, params, wt) &&
              serialize_wire_sig_params(entry, out_sig_params) else {
            out_sig_params.clear();
            return false;
        }
        out_ts = wt;
        return true;
    }
    return false;
}

fn validate_and_decode_signature_headers(
    headers:        const http::HeaderMap&,
    label:          const u8[:],
    params:         const http::SignatureParams&,
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
    var wire_ts = SigWireTimestamps { .. };
    guard find_verified_sig_params_line(
        comb_in[..],
        label,
        params,
        out_sig_params,
        wire_ts,
    ) else {
        return false;
    }
    guard validate_wire_signature_timestamps(wire_ts, now_sec) else {
        out_sig_params.clear();
        return false;
    }

    var comb_sig: u8[..4096] = [];
    guard headers.get_header(rfc::HEADER_SIGNATURE).len > 0 &&
          headers.get_combined(rfc::HEADER_SIGNATURE, comb_sig, 4096) else {
        out_sig_params.clear();
        return false;
    }

    let received_b64, ok = http::extract_signature_value(comb_sig[..], label);
    guard ok && core::base64_decode(received_b64, out_sig) else {
        out_sig_params.clear();
        out_sig.clear();
        return false;
    }
    return true;
}
