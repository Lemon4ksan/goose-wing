// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9110 Section 12.5: Content Negotiation Fields - Accept, Accept-Encoding, and Accept-Language.
namespace wing;

import std;
import core from "..";

// RFC 9110 Section 12.4.2: Quality Values - Maximum quality weight in integer milliths (1.000 == 1000).
const QVALUE_MAX_MILLITHS: i32 = 1000;

// Parses a single RFC 9110 Section 12.4.2 qvalue token ("0".."1.000") into milliths (0..1000).
//
// Example:
//   qstr = "0.85"
//   returns: 850, true
fn parse_qvalue_token(qstr: const u8[:]) -> i32, bool {
    guard qstr.len >= 1 && qstr.len <= 5 else { return 0, false; }
    if qstr == "1" || qstr == "1.0" || qstr == "1.00" || qstr == "1.000" {
        return QVALUE_MAX_MILLITHS, true;
    }
    if qstr == "0" {
        return 0, true;
    }
    let whole, frac, has_dot = qstr.split_once_byte('.');
    guard has_dot && whole == "0" && frac.len >= 1 && frac.len <= 3 else {
        return 0, false;
    }
    var padded: u8[..4] = [];
    let _ = padded.try_append(frac);
    while padded.len < 3 {
        let _ = padded.try_push('0');
    }
    let val, ok = padded[..].parse_i32_dec();
    guard ok && val >= 0 else { return 0, false; }
    return val, true;
}

// Parses the `q=` parameter from semicolon-delimited accept-params into milliths (0..1000).
// Returns (1000, true) when no `q=` parameter is present, or (0, false) on malformed `q=`.
//
// Example:
//   params = "level=1; q=0.85"
//   returns: 850, true
fn parse_qvalue_milliths(params: const u8[:]) -> i32, bool {
    guard params.len > 0 else { return QVALUE_MAX_MILLITHS, true; }
    var rem = params;
    while rem.len > 0 {
        let head, tail, has_semi = rem.split_once_unquoted_byte(';');
        rem = if has_semi { tail } else { "" };
        let param = head.trim_lws();
        if param.len == 0 { continue; }
        let k, v, has_eq = param.split_once_byte('=');
        if has_eq && k.trim_lws().eq_ascii_fold("q") {
            return parse_qvalue_token(v.trim_lws());
        }
    }
    return QVALUE_MAX_MILLITHS, true;
}

// Computes RFC 9110 Section 12.5.1 media-range match specificity against `candidate` ("type/subtype"):
// 3 = exact type/subtype, 2 = type/*, 1 = */* or *, 0 = no match.
inline fn match_media_specificity(pattern: const u8[:], candidate: const u8[:]) -> u8 {
    let pat = pattern.trim_lws();
    if pat == "*/*" || pat == "*" {
        return 1;
    }
    let cand_base, _, _ = candidate.split_once_byte(';');
    let p_type, p_sub, p_ok = pat.split_once_byte('/');
    let c_type, c_sub, c_ok = cand_base.trim_lws().split_once_byte('/');
    guard p_ok && c_ok else { return 0; }
    guard p_type.trim_lws().eq_ascii_fold(c_type.trim_lws()) else { return 0; }
    let ps = p_sub.trim_lws();
    if ps == "*" {
        return 2;
    }
    return if ps.eq_ascii_fold(c_sub.trim_lws()) { 3 } else { 0 };
}

fn score_accept_candidate(accept_hdr: const u8[:], cand: const u8[:]) -> i32, u8 {
    var cand_spec: u8  = 0;
    var cand_q:    i32 = -1;
    var rem = accept_hdr;
    while rem.len > 0 {
        let item, rest, has_comma = rem.split_once_unquoted_byte(',');
        rem = if has_comma { rest } else { "" };
        let trimmed = item.trim_lws();
        if trimmed.len == 0 { continue; }
        let media_range, params, has_semi = trimmed.split_once_unquoted_byte(';');
        let spec = match_media_specificity(media_range, cand);
        if spec == 0 { continue; }
        let q, ok = parse_qvalue_milliths(if has_semi { params } else { "" });
        if !ok { continue; }
        if spec > cand_spec || (spec == cand_spec && q > cand_q) {
            cand_spec = spec;
            cand_q = q;
        }
    }
    return cand_q, cand_spec;
}

// RFC 9110 Section 12.5.1: Accept - Selects the highest-ranked media type from `supported`
// against `accept_hdr`, honoring specificity precedence and explicit `q=0` exclusions.
//
// Example:
//   accept_hdr = "text/html;q=0.7, application/json;q=0.9"
//   supported = ["text/plain", "text/html", "application/json"]
//   returns: "application/json"
fn negotiate_accept(
    accept_hdr:   const u8[:],
    supported:    const (const u8[:])[:],
    default_mime: const u8[:] = "",
) -> const u8[:] {
    guard supported.len > 0 else { return default_mime; }
    if accept_hdr.trim_lws().len == 0 {
        return supported[0];
    }
    var best_idx:  i64 = -1;
    var best_q:    i32 = 0;
    var best_spec: u8  = 0;

    for idx in supported.len {
        let cand_q, cand_spec = score_accept_candidate(accept_hdr, supported[idx]);
        if cand_q > 0 && (cand_q > best_q || (cand_q == best_q && cand_spec > best_spec)) {
            best_idx = idx;
            best_q = cand_q;
            best_spec = cand_spec;
        }
    }
    return if best_idx >= 0 { supported[best_idx] } else { default_mime };
}

fn score_encoding_candidate(accept_enc: const u8[:], cand: const u8[:]) -> i32, u8 {
    var cand_spec: u8  = 0;
    var cand_q:    i32 = -1;
    var tok = core::make_byte_tokenizer(accept_enc, ',');
    while true {
        let item, has_more = core::token_next(tok);
        if !has_more { break; }
        let trimmed = item.trim_lws();
        if trimmed.len == 0 { continue; }
        let coding, params, has_semi = trimmed.split_once_byte(';');
        let c_trim = coding.trim_lws();
        let spec: u8 = if c_trim.eq_ascii_fold(cand) { 2 } else if c_trim == "*" { 1 } else { 0 };
        if spec == 0 { continue; }
        let q, ok = parse_qvalue_milliths(if has_semi { params } else { "" });
        if !ok { continue; }
        if spec > cand_spec || (spec == cand_spec && q > cand_q) {
            cand_spec = spec;
            cand_q = q;
        }
    }
    return cand_q, cand_spec;
}

// RFC 9110 Section 12.5.3: Accept-Encoding - Selects the preferred content coding (`zstd`, `br`, `gzip`)
// from `supported` according to client quality weights and `*` wildcard rules.
//
// Example:
//   accept_enc = "gzip;q=1.0, br;q=0.5, zstd;q=0"
//   supported = ["zstd", "br", "gzip"]
//   returns: "gzip"
fn negotiate_encoding(
    accept_enc: const u8[:],
    supported:  const (const u8[:])[:],
) -> const u8[:] {
    guard accept_enc.trim_lws().len > 0 && supported.len > 0 else { return ""; }
    var best_idx:  i64 = -1;
    var best_q:    i32 = 0;
    var best_spec: u8  = 0;

    for idx in supported.len {
        let cand_q, cand_spec = score_encoding_candidate(accept_enc, supported[idx]);
        if cand_q > 0 && (cand_q > best_q || (cand_q == best_q && cand_spec > best_spec)) {
            best_idx = idx;
            best_q = cand_q;
            best_spec = cand_spec;
        }
    }
    return if best_idx >= 0 { supported[best_idx] } else { "" };
}

inline fn match_language_specificity(rng: const u8[:], cand: const u8[:]) -> u8 {
    if rng.eq_ascii_fold(cand) {
        return 3;
    }
    if (cand.len > rng.len && cand.starts_with_fold(rng) && cand[rng.len] == '-')
        || (rng.len > cand.len && rng.starts_with_fold(cand) && rng[cand.len] == '-') {
        return 2;
    }
    return if rng == "*" { 1 } else { 0 };
}

fn score_language_candidate(accept_lang: const u8[:], cand: const u8[:]) -> i32, u8 {
    var cand_spec: u8  = 0;
    var cand_q:    i32 = -1;
    var tok = core::make_byte_tokenizer(accept_lang, ',');
    while true {
        let item, has_more = core::token_next(tok);
        if !has_more { break; }
        let trimmed = item.trim_lws();
        if trimmed.len == 0 { continue; }
        let tag_raw, params, has_semi = trimmed.split_once_byte(';');
        let spec = match_language_specificity(tag_raw.trim_lws(), cand);
        if spec == 0 { continue; }
        let q, ok = parse_qvalue_milliths(if has_semi { params } else { "" });
        if !ok { continue; }
        if spec > cand_spec || (spec == cand_spec && q > cand_q) {
            cand_spec = spec;
            cand_q = q;
        }
    }
    return cand_q, cand_spec;
}

// RFC 9110 Section 12.5.4: Accept-Language - Matches `Accept-Language` ranges
// against `supported` language tags with prefix fallback (e.g. "en-US" <-> "en").
//
// Example:
//   accept_lang = "fr-CH, fr;q=0.9, en;q=0.8"
//   supported = ["en", "fr"]
//   returns: "fr"
fn negotiate_language(
    accept_lang:  const u8[:],
    supported:    const (const u8[:])[:],
    default_lang: const u8[:] = "",
) -> const u8[:] {
    guard supported.len > 0 else { return default_lang; }
    if accept_lang.trim_lws().len == 0 { return supported[0]; }
    var best_idx:  i64 = -1;
    var best_q:    i32 = 0;
    var best_spec: u8  = 0;

    for idx in supported.len {
        let cand_q, cand_spec = score_language_candidate(accept_lang, supported[idx]);
        if cand_q > 0 && (cand_q > best_q || (cand_q == best_q && cand_spec > best_spec)) {
            best_idx = idx;
            best_q = cand_q;
            best_spec = cand_spec;
        }
    }
    return if best_idx >= 0 { supported[best_idx] } else { default_lang };
}
