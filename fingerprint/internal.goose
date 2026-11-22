// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for FoxIO JA4 (TLS) and JA4H (HTTP) fingerprint codecs.
namespace fingerprint_internal;

import std;
import core;
import .types;

// ---- JA4 & JA4H Internal Helpers -------------------------------------------

const JA4_STACK_LIST_CAP: i64 = 128; // Stack fast-path ceiling for TLS cipher/ext and cookie lists
const JA4_SNI_EXT_ID:     u16 = 0x0000; // RFC 6066 Section 3 (excluded from JA4 extension hash)
const JA4_ALPN_EXT_ID:    u16 = 0x0010; // RFC 7301 Section 3.1 (excluded from JA4 extension hash)

// Counts non-GREASE 16-bit TLS identifiers (RFC 8701).
fn count_non_grease_u16(vals: const u16[:]) -> i64 {
    var count: i64 = 0;
    for v in vals {
        if !rfc::is_grease_u16(v) {
            count = core::add_sat_i64(count, 1);
        }
    }
    return count;
}

// Filters non-GREASE 16-bit TLS identifiers into a fixed-capacity stack buffer.
// Returns false on capacity overflow so callers fall back without dropping values.
fn filter_grease_u16_bounded<B>(vals: const u16[:], out: B&) -> bool {
    for v in vals {
        if !rfc::is_grease_u16(v) {
            guard out.try_push(v) else { return false; }
        }
    }
    return true;
}

// Filters TLS extensions eligible for the JA4 extension hash (non-GREASE, excluding SNI and ALPN).
fn filter_ja4_hash_exts_bounded<B>(vals: const u16[:], out: B&) -> bool {
    for e in vals {
        if !rfc::is_grease_u16(e) && e != JA4_SNI_EXT_ID && e != JA4_ALPN_EXT_ID {
            guard out.try_push(e) else { return false; }
        }
    }
    return true;
}

// In-place insertion sort for 16-bit values (deterministic, zero-heap).
fn sort_u16(arr: u16[:]) {
    if arr.len <= 1 { return; }
    for i in 1..arr.len {
        let key = arr[i];
        var j = core::sub_sat_i64(i, 1);
        while j >= 0 && arr[j] > key {
            arr[core::add_sat_i64(j, 1)] = arr[j];
            j = core::sub_sat_i64(j, 1);
        }
        arr[core::add_sat_i64(j, 1)] = key;
    }
}

fn append_hex4<B>(val: u16, out: B&) {
    let hi = (val >> 8) as u8;
    let lo = (val & 0xFF) as u8;
    hi.format_u8_hex(out, false);
    lo.format_u8_hex(out, false);
}

fn sha256_update_hex4_csv(vals: const u16[:], ctx: core::Sha256Ctx&) {
    var tok: u8[..8] = [];
    for i in vals.len {
        tok.clear();
        if i > 0 { let _ = tok.try_push(','); }
        append_hex4(vals[i], tok);
        core::sha256_update(ctx, tok[..]);
    }
}

fn sha256_update_sig_algos_csv(
    sig_algorithms: const u16[:],
    has_prior_exts: bool,
    ctx:            core::Sha256Ctx&,
) -> bool {
    var tok: u8[..8] = [];
    var wrote_any = false;
    for s in sig_algorithms {
        if rfc::is_grease_u16(s) { continue; }
        tok.clear();
        if !wrote_any {
            if has_prior_exts { let _ = tok.try_push('_'); }
            wrote_any = true;
        } else {
            let _ = tok.try_push(',');
        }
        append_hex4(s, tok);
        core::sha256_update(ctx, tok[..]);
    }
    return wrote_any;
}

fn sha256_update_lower_ascii(ctx: core::Sha256Ctx&, s: const u8[:]) {
    var chunk: u8[..64] = [];
    for b in s {
        let _ = chunk.try_push(core::to_lower_ascii_byte(b));
        if chunk.len == 64 {
            core::sha256_update(ctx, chunk[..]);
            chunk.clear();
        }
    }
    if chunk.len > 0 {
        core::sha256_update(ctx, chunk[..]);
    }
}

fn append_two_digits<B>(n: i64, out: B&) {
    let d = min(max(n, 0), 99);
    let idx = core::add_sat_i64(d, d);
    let next_idx = core::add_sat_i64(idx, 1);
    guard idx >= 0 && next_idx < 200 else { return; }
    out.push(core::DIGITS_LUT[idx]);
    out.push(core::DIGITS_LUT[next_idx]);
}

// Finalizes SHA-256 and appends the first 12 lowercase hex characters (FoxIO truncation),
// or "000000000000" when no bytes were hashed.
fn finish_hash_12_hex<B>(ctx: core::Sha256Ctx&, has_data: bool, out: B&) {
    if !has_data {
        let _ = out.try_append("000000000000");
        return;
    }
    let sum = core::sha256_final(ctx);
    for i in 6 {
        sum[i].format_u8_hex(out, false);
    }
}

inline fn ja4_version_rank(v: u16) -> i32 {
    if v == 0x0304 || v == 0xFEFC { return 6; }
    if v == 0x0303 || v == 0xFEFD { return 5; }
    if v == 0x0302 { return 4; }
    if v == 0x0301 || v == 0xFEFF { return 3; }
    if v == 0x0300 { return 2; }
    if v == 0x0002 { return 1; }
    return 0;
}

// Maps highest supported TLS/DTLS version to 2-character JA4 code.
fn ja4_version_string(supported_versions: const u16[:]) -> const u8[:] {
    var best_ver:  u16 = 0;
    var best_rank: i32 = 0;
    for v in supported_versions {
        if !rfc::is_grease_u16(v) {
            let r = ja4_version_rank(v);
            if r > best_rank {
                best_rank = r;
                best_ver = v;
            }
        }
    }
    if best_ver == 0x0304 { return "13"; } // TLS 1.3
    if best_ver == 0x0303 { return "12"; } // TLS 1.2
    if best_ver == 0x0302 { return "11"; } // TLS 1.1
    if best_ver == 0x0301 { return "10"; } // TLS 1.0
    if best_ver == 0x0300 { return "s3"; } // SSL 3.0
    if best_ver == 0x0002 { return "s2"; } // SSL 2.0
    if best_ver == 0xFEFC { return "d3"; } // DTLS 1.3
    if best_ver == 0xFEFD { return "d2"; } // DTLS 1.2
    if best_ver == 0xFEFF { return "d1"; } // DTLS 1.0
    return "00";
}

// Extracts 2-character ALPN code, falling back to nibble hex when non-alphanumeric.
fn ja4_alpn_string<B>(alpn_protocol: const u8[:], out: B&) {
    let head, _, has_comma = alpn_protocol.split_once_byte(',');
    let first_proto = if has_comma { head } else { alpn_protocol };
    guard first_proto.len > 0 else {
        out.append("00");
        return;
    }
    let b_first = first_proto[0];
    let b_last = first_proto[core::sub_sat_i64(first_proto.len, 1)];

    if core::is_ascii_alphanumeric(b_first) && core::is_ascii_alphanumeric(b_last) {
        out.push(b_first);
        out.push(b_last);
    } else {
        let combined = (b_first & 0xF0) | (b_last & 0x0F);
        combined.format_u8_hex(out, false);
    }
}

fn hash_ja4_sorted_ciphers<B>(ciphers: u16[:], out: B&) {
    sort_u16(ciphers);
    var ctx = core::Sha256Ctx { .. };
    sha256_update_hex4_csv(ciphers, ctx);
    finish_hash_12_hex(ctx, ciphers.len > 0, out);
}

fn append_ja4_ciphers_hash<B>(ciphers: const u16[:], out: B&) {
    var stack_ciphers: u16[..128] = [];
    if filter_grease_u16_bounded(ciphers, stack_ciphers) {
        hash_ja4_sorted_ciphers(stack_ciphers[..], out);
        return;
    }
    var dyn_ciphers: u16[>..] = [];
    for v in ciphers {
        if !rfc::is_grease_u16(v) { dyn_ciphers.push(v); }
    }
    hash_ja4_sorted_ciphers(dyn_ciphers[..], out);
}

fn hash_ja4_sorted_exts<B>(exts: u16[:], sig_algorithms: const u16[:], out: B&) {
    sort_u16(exts);
    var ctx = core::Sha256Ctx { .. };
    sha256_update_hex4_csv(exts, ctx);
    let has_sigs = sha256_update_sig_algos_csv(sig_algorithms, exts.len > 0, ctx);
    finish_hash_12_hex(ctx, exts.len > 0 || has_sigs, out);
}

fn append_ja4_extensions_hash<B>(
    extensions:     const u16[:],
    sig_algorithms: const u16[:],
    out:            B&,
) {
    var stack_exts: u16[..128] = [];
    if filter_ja4_hash_exts_bounded(extensions, stack_exts) {
        hash_ja4_sorted_exts(stack_exts[..], sig_algorithms, out);
        return;
    }
    var dyn_exts: u16[>..] = [];
    for e in extensions {
        if !rfc::is_grease_u16(e) && e != JA4_SNI_EXT_ID && e != JA4_ALPN_EXT_ID {
            dyn_exts.push(e);
        }
    }
    hash_ja4_sorted_exts(dyn_exts[..], sig_algorithms, out);
}

fn is_bytes_less(a: const u8[:], b: const u8[:]) -> bool {
    let min_len = min(a.len, b.len);
    for i in min_len {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    return a.len < b.len;
}

fn is_cookie_pair_less(
    names:  const u8[:][:],
    values: const u8[:][:],
    a_idx:  i64,
    b_idx:  i64,
) -> bool {
    if names[a_idx] != names[b_idx] {
        return is_bytes_less(names[a_idx], names[b_idx]);
    }
    let val_a = if a_idx < values.len { values[a_idx] } else { "" };
    let val_b = if b_idx < values.len { values[b_idx] } else { "" };
    return is_bytes_less(val_a, val_b);
}

fn sort_cookie_indices(
    names:  const u8[:][:],
    values: const u8[:][:],
    order:  i64[:],
) {
    if order.len <= 1 { return; }
    for i in 1..order.len {
        let key_idx = order[i];
        var j = core::sub_sat_i64(i, 1);
        while j >= 0 && is_cookie_pair_less(names, values, key_idx, order[j]) {
            order[core::add_sat_i64(j, 1)] = order[j];
            j = core::sub_sat_i64(j, 1);
        }
        order[core::add_sat_i64(j, 1)] = key_idx;
    }
}

fn append_ja4h_language<B>(accept_lang: const u8[:], out: B&) {
    guard accept_lang.len > 0 else {
        out.append("0000");
        return;
    }
    var count: u64 = 0;
    for b in accept_lang {
        if count == 4 || b == ',' || b == ';' { break; }
        if core::is_ascii_alphanumeric(b) {
            out.push(core::to_lower_ascii_byte(b));
            count = core::add_sat_u64(count, 1);
        }
    }
    while count < 4 {
        out.push('0');
        count = core::add_sat_u64(count, 1);
    }
}

fn fill_cookie_order_bounded<B>(n: i64, out: B&) -> bool {
    for i in n {
        guard out.try_push(i) else { return false; }
    }
    return true;
}

fn append_ja4h_sorted_cookies_hashes<B>(
    cookie_names:  const u8[:][:],
    cookie_values: const u8[:][:],
    order:         i64[:],
    out:           B&,
) {
    sort_cookie_indices(cookie_names, cookie_values, order);

    var ctx_names = core::Sha256Ctx { .. };
    var ctx_vals = core::Sha256Ctx { .. };
    for i in order.len {
        if i > 0 {
            core::sha256_update(ctx_names, ",");
            core::sha256_update(ctx_vals, ",");
        }
        let idx = order[i];
        core::sha256_update(ctx_names, cookie_names[idx]);
        core::sha256_update(ctx_vals, cookie_names[idx]);
        core::sha256_update(ctx_vals, "=");
        if idx < cookie_values.len {
            core::sha256_update(ctx_vals, cookie_values[idx]);
        }
    }
    finish_hash_12_hex(ctx_names, order.len > 0, out);
    out.push('_');
    finish_hash_12_hex(ctx_vals, order.len > 0, out);
}

fn append_ja4h_cookies_hash<B>(
    cookie_names:  const u8[:][:],
    cookie_values: const u8[:][:],
    out:           B&,
) {
    if cookie_names.len == 0 {
        out.append("000000000000_000000000000");
        return;
    }
    var stack_order: i64[..128] = [];
    if cookie_names.len <= JA4_STACK_LIST_CAP && fill_cookie_order_bounded(cookie_names.len, stack_order) {
        append_ja4h_sorted_cookies_hashes(cookie_names, cookie_values, stack_order[..], out);
        return;
    }
    var dyn_order: i64[>..] = [];
    for i in cookie_names.len { dyn_order.push(i); }
    append_ja4h_sorted_cookies_hashes(cookie_names, cookie_values, dyn_order[..], out);
}

inline fn ja4h_proto_string(proto: const u8[:]) -> const u8[:] {
    if proto.eq_ascii_fold("HTTP/1.0") || proto == "1.0" { return "10"; }
    if proto.eq_ascii_fold("HTTP/1.1") || proto == "1.1" { return "11"; }
    let is_h2 = proto.eq_ascii_fold("HTTP/2") || proto.eq_ascii_fold("HTTP/2.0") || proto.eq_ascii_fold("h2");
    if is_h2 || proto == "2" || proto == "2.0" {
        return "20";
    }
    let is_h3 = proto.eq_ascii_fold("HTTP/3") || proto.eq_ascii_fold("HTTP/3.0") || proto.eq_ascii_fold("h3");
    if is_h3 || proto == "3" || proto == "3.0" {
        return "30";
    }
    return "00";
}

// Counts non-excluded HTTP headers, resolves cookie/referer flags, and streams JA4H_b digest.
fn summarize_ja4h_headers(
    header_names: const u8[:][:],
    flags:        fingerprint::Ja4hFlags,
    has_cookies:  bool,
) -> i64, fingerprint::Ja4hFlags, u8[..12] {
    var ctx = core::Sha256Ctx { .. };
    var count: i64 = 0;
    var res = fingerprint::Ja4hFlags {
        has_cookie:  flags.has_cookie || has_cookies,
        has_referer: flags.has_referer,
    };
    for h in header_names {
        if h.len == 0 || h[0] == ':' { continue; }
        if h.eq_ascii_fold("cookie") {
            res.has_cookie = true;
            continue;
        }
        if h.eq_ascii_fold("referer") {
            res.has_referer = true;
            continue;
        }
        if count > 0 { core::sha256_update(ctx, ","); }
        sha256_update_lower_ascii(ctx, h);
        count = core::add_sat_i64(count, 1);
    }
    var hash12: u8[..12] = [];
    finish_hash_12_hex(ctx, count > 0, hash12);
    return count, res, hash12;
}
