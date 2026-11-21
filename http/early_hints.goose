// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP 103 Early Hints (RFC 8297) and Link Preload / Preconnect Engine.
// Zero-heap parser for informational 103 responses:
// - Extracts `Link: <uri>; rel=preload; as=...` and `Link: <origin>; rel=preconnect`
// - Enables client-side speculative connection pre-warming and asset prefetching
//   before the final 200 OK response arrives.
namespace http;

import std;
import core;
import .headers;
import .mime;
import http.ext_internal;

// ---- Early Hints Models -------------------------------------------------

struct EarlyHintLink {
    uri:         u8[..256] = [],
    rel:         u8[..32]  = [], // "preload", "preconnect", "dns-prefetch"
    as_type:     u8[..32]  = [], // "style", "script", "font", "image", "fetch"
    crossorigin: bool      = false,
}

struct EarlyHintsResponse {
    links:    EarlyHintLink[..8] = [],
    is_valid: bool               = false,
}

// ---- RFC 8288 / RFC 8297 Link Header Parser -----------------------------

// Parses RFC 8288 `Link` header: `<uri>; rel=...; as=...`
//
// Example:
//   raw = "</style.css>; rel=preload, </app.js>; rel=preload"
//   returns: true, out_links has 2 entries
fn parse_link_header<E>(raw: const u8[:], out_links: E&) -> bool {
    out_links.clear();
    var committed = false;
    defer if !committed { out_links.clear(); };
    var rem = raw;
    while rem.len > 0 {
        rem = rem.trim_start_bytes(" \t,");
        guard rem.len > 0 else { break; }

        let entry_len = http_internal::find_link_entry_end(rem);
        let entry_str = rem[..entry_len].trim_lws();
        rem = if entry_len < rem.len { rem[entry_len + 1..] } else { rem[entry_len..] };

        var link = EarlyHintLink { .. };
        guard http_internal::parse_single_link(entry_str, link) else { return false; }
        guard out_links.try_push(link) else { return false; }
    }
    committed = true;
    return true;
}

// Parses a 103 Early Hints informational block (RFC 8297 §2).
//
// Example:
//   status = 103, raw_link_header = "</style.css>; rel=preload"
//   returns: resp with 1 link, ok = true
fn parse_early_hints(status: u16, raw_link_header: const u8[:]) -> EarlyHintsResponse, bool {
    var resp = EarlyHintsResponse { .. };
    guard status == rfc::STATUS_EARLY_HINTS else { return resp, false; }

    guard parse_link_header(raw_link_header, resp.links) else { return resp, false; }
    resp.is_valid = true;
    return resp, true;
}

// Checks if link requests a preconnect action
fn early_hint_is_preconnect(link: const EarlyHintLink&) -> bool {
    return link.rel[..].eq_ascii_fold("preconnect") || link.rel[..].eq_ascii_fold("dns-prefetch");
}

// Checks if link requests asset preloading
fn early_hint_is_preload(link: const EarlyHintLink&) -> bool {
    return link.rel[..].eq_ascii_fold("preload");
}

// ---- Server-Side 103 Early Hints Serializer & CASPer Cookie Digest --------

// Serializes an HTTP/1.1 `103 Early Hints` response block (RFC 8297 §2).
// Suppresses output and returns `false` if the client sent `no-early-hints: 1`
// or if `hints.links` is empty.
fn format_early_hints_http1<B>(
    hints:              const EarlyHintsResponse&,
    req_no_early_hints: const u8[:],
    out:                B&,
) -> bool {
    let trimmed_opt = req_no_early_hints.trim_lws();
    guard trimmed_opt != "1" && hints.links.len > 0 else { return false; }
    var scratch: u8[..2048] = [];
    scratch.append("HTTP/1.1 103 Early Hints\r\n");
    for &link in hints.links {
        guard http_internal::format_single_early_hint_link(link, scratch) else { return false; }
    }
    guard scratch.try_append("\r\n") && out.try_append(scratch[..]) else { return false; }
    return true;
}

// H2O CASPer (Cache-Aware Server Push / Early Hints) Golomb-Coded Set state.
struct CasperSet {
    keys:           u64[..128] = [],
    capacity_bits:  u8         = 13,
    remainder_bits: u8         = 6,
}

// Checks whether `(path, etag)` is already present in `set`.
// Returns `true` if already present (caller should suppress duplicate hint),
// or `false` if newly inserted (caller should emit hint).
fn casper_lookup_and_insert(set: CasperSet&, path: const u8[:], etag: const u8[:]) -> bool {
    let key = http_internal::compute_casper_key(set, path, etag);
    let ins_idx, found = http_internal::find_casper_key_slot(set, key);
    if found {
        return true;
    }
    guard set.keys.try_push(key) else { return false; }
    var pos: u64 = core::sub_sat_u64(set.keys.len as u64, 1);
    let target = ins_idx as u64;
    while pos > target {
        let prev = core::sub_sat_u64(pos, 1);
        set.keys[pos as i64] = set.keys[prev as i64];
        pos = prev;
    }
    set.keys[target as i64] = key;
    return false;
}

// Encodes sorted `CasperSet` keys using Golomb-Rice delta coding into Base64URL cookie value.
//
// Example:
//   set.keys = [10, 25], out_cookie = []
//   returns: true, out_cookie populated with Base64URL Golomb-Rice bitstream
fn encode_casper_cookie<B>(set: const CasperSet&, out_cookie: B&) -> bool {
    var raw_bits: u8[..256] = [];
    var cur_byte: u64       = 0;
    var bit_pos:  u64       = 0;
    let rem_bits = min(set.remainder_bits as u64, 16);
    guard rem_bits > 0 else { return false; }
    let r_mask = 0xFFFFFFFFFFFFFFFF >> core::sub_sat_u64(64, rem_bits);
    var prev: u64 = 0;
    for k in set.keys {
        let delta = if k >= prev { core::sub_sat_u64(k, prev) } else { 0 };
        prev = k;
        let q = delta >> rem_bits;
        let r = delta & r_mask;
        guard q <= 512 else { return false; }
        var q_rem: u64 = q;
        while q_rem > 0 {
            q_rem = core::sub_sat_u64(q_rem, 1);
            guard http_internal::append_casper_bit(raw_bits, cur_byte, bit_pos, 1) else { return false; }
        }
        guard http_internal::append_casper_bit(raw_bits, cur_byte, bit_pos, 0) else { return false; }
        var b_idx: u64 = rem_bits;
        while b_idx > 0 {
            b_idx = core::sub_sat_u64(b_idx, 1);
            let bit = (r >> b_idx) & 1;
            guard http_internal::append_casper_bit(raw_bits, cur_byte, bit_pos, bit) else { return false; }
        }
    }
    if bit_pos > 0 {
        let pad_shift = core::sub_sat_u64(8, bit_pos);
        let padded = (cur_byte << pad_shift) & 0xFF;
        guard raw_bits.try_push(padded as u8) else { return false; }
    }
    out_cookie.clear();
    let enc_cap = core::add_sat_u64(raw_bits.len as u64, raw_bits.len as u64);
    guard enc_cap <= (out_cookie.cap as u64) else { return false; }
    core::base64url_encode(raw_bits[..], out_cookie);
    return true;
}

// Decodes a Base64URL Golomb-Rice CASPer cookie into `set.keys`.
//
// Example:
//   cookie = "B9A", set = CasperSet { .. }
//   returns: true, set.keys populated with decoded sorted keys
fn decode_casper_cookie(cookie: const u8[:], set: CasperSet&) -> bool {
    var raw_bits: u8[..256] = [];
    guard core::base64url_decode(cookie, raw_bits) else { return false; }
    let rem_bits = min(set.remainder_bits as u64, 16);
    guard rem_bits > 0 else { return false; }
    var byte_idx: i64 = 0;
    var bit_pos:  u64 = 0;
    var cur_key:  u64 = 0;
    while byte_idx < raw_bits.len && set.keys.len < set.keys.cap {
        let delta, has_val, valid = http_internal::decode_casper_golomb_step(raw_bits[..], rem_bits, byte_idx, bit_pos);
        guard valid else { return false; }
        guard has_val else { break; }
        cur_key = core::add_sat_u64(cur_key, delta);
        set.keys.push(cur_key);
    }
    return true;
}
