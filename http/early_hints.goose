// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP 103 Early Hints (RFC 8297) and Link Preload / Preconnect Engine.
// Zero-heap parser for informational 103 responses:
// - Extracts `Link: <uri>; rel=preload; as=...` and `Link: <origin>; rel=preconnect`
// - Enables client-side speculative connection pre-warming and asset prefetching
//   before the final 200 OK response arrives.
namespace wing;

import std;
import core from "..";
import .headers;
import .mime;

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

// Parses single Link parameter: e.g. `rel=preload` or `as=style` (RFC 8288 §3).
//
// Example:
//   param_str = "rel=preload"
//   mutates link.rel to "preload"
fn parse_link_param(param_str: const u8[:], link: EarlyHintLink&) -> bool {
    let p_name_raw, p_val_raw, has_eq = param_str.split_once_byte('=');
    if !has_eq {
        let p_name = param_str.trim_lws();
        guard is_valid_header_name(p_name) else { return false; }
        if p_name.eq_ascii_fold("crossorigin") {
            link.crossorigin = true;
        }
        return true;
    }

    let p_name = p_name_raw.trim_lws();
    let p_val_trim = p_val_raw.trim_lws();
    guard is_valid_header_name(p_name) else { return false; }
    var p_val: u8[..256] = [];
    guard decode_token_or_quoted_param(p_val_trim, p_val, 256) else { return false; }

    if p_name.eq_ascii_fold("rel") {
        guard link.rel.len == 0 else { return true; }
        guard link.rel.try_append(p_val[..]) else { return false; }
    } else if p_name.eq_ascii_fold("as") {
        guard link.as_type.len == 0 else { return true; }
        guard link.as_type.try_append(p_val[..]) else { return false; }
    } else if p_name.eq_ascii_fold("crossorigin") {
        link.crossorigin = true;
    }
    return true;
}

fn find_link_entry_end(s: const u8[:]) -> i64 {
    var in_quotes = false;
    var in_angle = false;
    var escaped = false;
    for i in s.len {
        let b = s[i];
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes && b == '\\' {
            escaped = true;
            continue;
        }
        if b == '"' && !in_angle {
            in_quotes = !in_quotes;
        } else if b == '<' && !in_quotes {
            in_angle = true;
        } else if b == '>' && !in_quotes {
            in_angle = false;
        } else if !in_quotes && !in_angle && b == ',' {
            return i;
        }
    }
    return s.len;
}

fn read_next_link_param(rem: const u8[:]) -> const u8[:], const u8[:] {
    let s = rem.trim_start_bytes(" \t;");
    guard s.len > 0 else { return "", ""; }
    let p_len = s.find_unquoted_byte(';');
    let param = s[..p_len].trim_lws();
    let next_rem = if p_len < s.len { s[p_len + 1..] } else { s[..0] };
    return param, next_rem;
}

// Parses RFC 8288 semicolon-separated link parameters.
//
// Example:
//   params_str = "; rel=preload; as=style"
//   returns: true, link populated with rel="preload", as_type="style"
fn parse_link_params(params_str: const u8[:], link: EarlyHintLink&) -> bool {
    var rem = params_str;
    while rem.len > 0 {
        let param, next_rem = read_next_link_param(rem);
        guard param.len > 0 else { break; }
        guard parse_link_param(param, link) else { return false; }
        rem = next_rem;
    }
    return true;
}

// Parses a single Link element enclosed in angle brackets with parameters.
//
// Example:
//   entry_str = "</style.css>; rel=preload; as=style"
//   returns: true, link populated with uri="/style.css", rel="preload", as_type="style"
fn parse_single_link(entry_str: const u8[:], link: EarlyHintLink&) -> bool {
    guard entry_str.len > 2 && entry_str[0] == '<' else { return false; }
    let rel_close = entry_str[1..].index_of_byte('>');
    guard rel_close >= 0 else { return false; }
    let close_idx = 1 + rel_close;
    let uri_slice = entry_str[1..close_idx];
    // Reject empty URI (<>) and enforce capacity
    guard uri_slice.len > 0 && link.uri.try_append(uri_slice) else { return false; }

    let after_uri = entry_str[close_idx + 1..].trim_lws_start();
    if after_uri.len > 0 {
        guard after_uri[0] == ';' else { return false; }
    }
    return parse_link_params(after_uri, link);
}

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

        let entry_len = find_link_entry_end(rem);
        let entry_str = rem[..entry_len].trim_lws();
        rem = if entry_len < rem.len { rem[entry_len + 1..] } else { rem[entry_len..] };

        var link = EarlyHintLink { .. };
        guard parse_single_link(entry_str, link) else { return false; }
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

// Formats a single `EarlyHintLink` into an HTTP `Link: <uri>; ...` header line.
fn format_single_early_hint_link<B>(link: const EarlyHintLink&, out: B&) -> bool {
    guard link.uri.len > 0 else { return false; }
    let base_needed = core::add_sat_u64(link.uri.len as u64, 64);
    guard core::add_sat_u64(out.len as u64, base_needed) <= (out.cap as u64) else { return false; }
    out.append("Link: <");
    out.append(link.uri[..]);
    out.push('>');
    if link.rel.len > 0 {
        out.append("; rel=");
        out.append(link.rel[..]);
    }
    if link.as_type.len > 0 {
        out.append("; as=");
        out.append(link.as_type[..]);
    }
    if link.crossorigin {
        out.append("; crossorigin");
    }
    out.append("\r\n");
    return true;
}

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
        guard format_single_early_hint_link(link, scratch) else { return false; }
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

// Computes truncated fingerprint for (path, etag) bounded by `(capacity_bits + remainder_bits)` bits.
fn compute_casper_key(set: const CasperSet&, path: const u8[:], etag: const u8[:]) -> u64 {
    let h_path = core::fnv1a_64(path);
    let h_etag = core::fnv1a_64(etag);
    let combined = core::hash_combine_u64(h_path, h_etag);
    let total_bits = min(core::add_sat_u64(set.capacity_bits, set.remainder_bits), 14);
    let drop_bits = core::sub_sat_u64(64, total_bits);
    let mask = if total_bits == 0 { 0 } else { 0xFFFFFFFFFFFFFFFF >> drop_bits };
    return combined & mask;
}

// Looks up `key` in sorted `set.keys`; returns `(found, insert_idx)`.
fn find_casper_key_slot(set: const CasperSet&, key: u64) -> bool, i64 {
    var lo: u64 = 0;
    var hi: u64 = set.keys.len as u64;
    while lo < hi {
        let mid = core::add_sat_u64(lo, core::sub_sat_u64(hi, lo) >> 1);
        let cur = set.keys[mid as i64];
        if cur == key {
            return true, mid as i64;
        }
        if cur < key {
            lo = core::add_sat_u64(mid, 1);
        } else {
            hi = mid;
        }
    }
    return false, lo as i64;
}

// Checks whether `(path, etag)` is already present in `set`.
// Returns `true` if already present (caller should suppress duplicate hint),
// or `false` if newly inserted (caller should emit hint).
fn casper_lookup_and_insert(set: CasperSet&, path: const u8[:], etag: const u8[:]) -> bool {
    let key = compute_casper_key(set, path, etag);
    let found, ins_idx = find_casper_key_slot(set, key);
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

inline fn append_casper_bit<B>(out: B&, cur_byte: u64&, bit_pos: u64&, bit: u64) -> bool {
    cur_byte = ((cur_byte << 1) | (bit & 1)) & 0xFF;
    bit_pos = core::add_sat_u64(bit_pos, 1);
    if bit_pos == 8 {
        let b_val: u8 = if cur_byte == 0 { 0 } else { (cur_byte & 0xFF) as u8 };
        guard out.try_push(b_val) else { return false; }
        cur_byte = 0;
        bit_pos = 0;
    }
    return true;
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
            guard append_casper_bit(raw_bits, cur_byte, bit_pos, 1) else { return false; }
        }
        guard append_casper_bit(raw_bits, cur_byte, bit_pos, 0) else { return false; }
        var b_idx: u64 = rem_bits;
        while b_idx > 0 {
            b_idx = core::sub_sat_u64(b_idx, 1);
            let bit = (r >> b_idx) & 1;
            guard append_casper_bit(raw_bits, cur_byte, bit_pos, bit) else { return false; }
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

inline fn read_casper_bit(raw: const u8[:], byte_idx: i64&, bit_pos: u64&) -> u64, bool {
    guard byte_idx < raw.len else { return 0, false; }
    let shift = core::sub_sat_u64(7, bit_pos);
    let bit = (raw[byte_idx] as u64 >> shift) & 1;
    bit_pos = core::add_sat_u64(bit_pos, 1);
    if bit_pos == 8 {
        bit_pos = 0;
        byte_idx = core::add_sat_i64(byte_idx, 1);
    }
    return bit, true;
}

// Decodes a single Golomb-Rice delta step from `raw` at `(byte_idx, bit_pos)`.
//
// Example:
//   raw = [0x40], rem_bits = 6, byte_idx = 0, bit_pos = 0
//   returns: delta = 16, has_val = true, valid = true, byte_idx = 0, bit_pos = 7
inline fn decode_casper_golomb_step(
    raw:      const u8[:],
    rem_bits: u64,
    byte_idx: i64&,
    bit_pos:  u64&,
) -> u64, bool, bool {
    var q: u64 = 0;
    var got_zero = false;
    while byte_idx < raw.len {
        let b, ok_b = read_casper_bit(raw, byte_idx, bit_pos);
        guard ok_b else { break; }
        if b == 0 {
            got_zero = true;
            break;
        }
        q = core::add_sat_u64(q, 1);
        guard q <= 512 else { return 0, false, false; }
    }
    guard got_zero else { return 0, false, true; }
    var r:     u64 = 0;
    var r_idx: u64 = rem_bits;
    while r_idx > 0 {
        r_idx = core::sub_sat_u64(r_idx, 1);
        let rb, ok_r = read_casper_bit(raw, byte_idx, bit_pos);
        guard ok_r else { return 0, false, true; }
        r = core::add_sat_u64(core::add_sat_u64(r, r), rb);
    }
    var q_scaled: u64 = q;
    var s_idx:    u64 = rem_bits;
    while s_idx > 0 {
        s_idx = core::sub_sat_u64(s_idx, 1);
        q_scaled = core::add_sat_u64(q_scaled, q_scaled);
    }
    return core::add_sat_u64(q_scaled, r), true, true;
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
        let delta, has_val, valid = decode_casper_golomb_step(raw_bits[..], rem_bits, byte_idx, bit_pos);
        guard valid else { return false; }
        guard has_val else { break; }
        cur_key = core::add_sat_u64(cur_key, delta);
        set.keys.push(cur_key);
    }
    return true;
}
