// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal Digest header serialization and challenge resolution helpers.
namespace auth_internal;

import std;
import core;
import rfc.http;
import .types;
import .internal;
import .digest_core;

inline fn try_mark_digest_param(seen_mask: u32&, bit: u32) -> bool {
    guard (seen_mask & bit) == 0 else { return false; }
    seen_mask = seen_mask | bit;
    return true;
}

enum DigestParamStatus {
    Unhandled,
    Applied,
    Invalid,
}

inline fn set_unique_digest_buf<B>(
    dst:       B&,
    val:       const u8[:],
    seen_mask: u32&,
    bit:       u32,
) -> bool {
    return (seen_mask & bit) == 0 && dst.try_set(val) && try_mark_digest_param(seen_mask, bit);
}

inline fn digest_param_status_from_bool(ok: bool) -> DigestParamStatus {
    return if ok { DigestParamStatus.Applied } else { DigestParamStatus.Invalid };
}

fn apply_digest_core_param(
    chal:      auth::DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
) -> DigestParamStatus {
    if key.eq_ascii_fold("realm") {
        return digest_param_status_from_bool(set_unique_digest_buf(chal.realm, val, seen_mask, 1));
    }
    if key.eq_ascii_fold("nonce") {
        return digest_param_status_from_bool(set_unique_digest_buf(chal.nonce, val, seen_mask, 2));
    }
    if key.eq_ascii_fold("algorithm") {
        guard set_unique_digest_buf(chal.algorithm, val, seen_mask, 4) else {
            return DigestParamStatus.Invalid;
        }
        chal.has_explicit_algo = true;
        return DigestParamStatus.Applied;
    }
    if key.eq_ascii_fold("qop") {
        return digest_param_status_from_bool(val.len > 0 && set_unique_digest_buf(chal.qop, val, seen_mask, 8));
    }
    return DigestParamStatus.Unhandled;
}

inline fn record_digest_ext_key(key: const u8[:], seen_mask: u32&, ext_keys: u8[..64][..16]&) -> bool {
    // RFC 9110 Section 11.2: Authentication Parameters - parameter names MUST NOT occur more than once per challenge
    for &seen_ext in ext_keys {
        if seen_ext[..].eq_ascii_fold(key) { return false; }
    }
    var kbuf: u8[..64] = [];
    guard kbuf.try_set(key) && ext_keys.try_push(kbuf) else { return false; }
    seen_mask = seen_mask | 512;
    return true;
}

fn apply_digest_opt_param(
    chal:      auth::DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
    ext_keys:  u8[..64][..16]&,
) -> bool {
    if key.eq_ascii_fold("opaque") {
        return set_unique_digest_buf(chal.opaque, val, seen_mask, 16);
    }
    if key.eq_ascii_fold("domain") {
        return set_unique_digest_buf(chal.domain, val, seen_mask, 32);
    }
    if key.eq_ascii_fold("stale") {
        // RFC 7616 Section 3.3: The WWW-Authenticate Response Header Field - non-"true" stale values mean false
        guard val.len > 0 && try_mark_digest_param(seen_mask, 64) else { return false; }
        chal.stale = val.eq_ascii_fold("true");
        return true;
    }
    if key.eq_ascii_fold("userhash") {
        let is_true = val.eq_ascii_fold("true");
        guard (is_true || val.eq_ascii_fold("false")) && try_mark_digest_param(seen_mask, 128) else { return false; }
        chal.userhash = is_true;
        return true;
    }
    if key.eq_ascii_fold("charset") {
        return val.eq_ascii_fold("UTF-8") && try_mark_digest_param(seen_mask, 256);
    }
    return record_digest_ext_key(key, seen_mask, ext_keys);
}

fn apply_digest_param(
    chal:      auth::DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
    ext_keys:  u8[..64][..16]&,
) -> bool {
    let core_st = apply_digest_core_param(chal, key, val, seen_mask);
    if core_st != DigestParamStatus.Unhandled {
        return core_st == DigestParamStatus.Applied;
    }
    return apply_digest_opt_param(chal, key, val, seen_mask, ext_keys);
}

// Advances `idx` past any leading whitespace, commas, or line breaks (RFC 7616 §3.3).
//
// Example:
//   raw = ",  realm=\"api\"", idx = 0
//   advances `idx` to 3 (pointing to 'r')
fn skip_whitespace_and_commas(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..].trim_start_bytes(" \t,\r\n");
    idx = core::sub_sat_i64(raw.len, rem.len);
}

// Advances `idx` past optional leading "Digest " scheme token (RFC 7616 §3.3).
//
// Example:
//   raw = "Digest realm=\"api\"", idx = 0
//   advances `idx` to 7 (pointing to 'r')
inline fn skip_digest_scheme(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    guard rem.len >= 7 && rem[..6].eq_ascii_fold("digest") else { return; }
    guard rem[6] == ' ' || rem[6] == '\t' else { return; }
    idx = core::add_sat_i64(idx, 7);
}

inline fn is_ascii_hex_str(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_ascii_hexdigit(b) else { return false; }
    }
    return true;
}

fn append_escaped_digest_param<B>(out: B&, val: const u8[:]) -> bool {
    for b in val {
        guard b != '\r' && b != '\n' && b != 0 else { return false; }
        if b == '"' || b == '\\' {
            guard out.try_push('\\' as u8) else { return false; }
        }
        guard out.try_push(b) else { return false; }
    }
    return true;
}

fn serialize_digest_opt_kv<B>(
    out:        B&,
    active_qop: const u8[:],
    nc_str:     const u8[:],
    cnonce:     const u8[:],
    opaque:     const u8[:],
    userhash:   bool,
) -> bool {
    if active_qop.len > 0 {
        guard out.try_append(", qop=") && out.try_append(active_qop) else { return false; }
        guard out.try_append(", nc=") && out.try_append(nc_str) else { return false; }
        guard out.try_append(", cnonce=\"") && append_escaped_digest_param(out, cnonce) && out.try_push('"' as u8) else {
            return false;
        }
    } else if cnonce.len > 0 {
        guard out.try_append(", cnonce=\"") && append_escaped_digest_param(out, cnonce) && out.try_push('"' as u8) else {
            return false;
        }
    }

    if opaque.len > 0 {
        guard out.try_append(", opaque=\"") && append_escaped_digest_param(out, opaque) && out.try_push('"' as u8) else {
            return false;
        }
    }

    if userhash {
        guard out.try_append(", userhash=true") else { return false; }
    }

    return true;
}

inline fn sync_opt_buf<B>(dst: B&, src: const u8[:]) -> bool {
    guard src.len > 0 else { return true; }
    return dst.try_set(src);
}

inline fn is_md5_digest_algo(algo: const u8[:]) -> bool {
    return algo.eq_ascii_fold(rfc::DIGEST_ALGO_MD5) || algo.eq_ascii_fold(rfc::DIGEST_ALGO_MD5_SESS);
}

inline fn resolve_stale_digest_algo(
    stored_algo: const u8[:],
    incoming:    const auth::DigestChallenge&,
) -> const u8[:], bool {
    let is_implicit_md5 = !incoming.has_explicit_algo && incoming.algorithm[..].eq_ascii_fold(rfc::DIGEST_ALGO_MD5);
    if is_implicit_md5 && stored_algo.len > 0 {
        return stored_algo, rfc::is_supported_digest_algo(stored_algo);
    }
    guard rfc::is_supported_digest_algo(incoming.algorithm[..]) else { return "", false; }
    if stored_algo.len > 0 && !is_md5_digest_algo(stored_algo) && is_md5_digest_algo(incoming.algorithm[..]) {
        return "", false;
    }
    return incoming.algorithm[..], true;
}

fn serialize_digest_core_kv<B>(
    out:            B&,
    effective_user: const u8[:],
    realm:          const u8[:],
    nonce:          const u8[:],
    uri:            const u8[:],
    algo:           const u8[:],
    response_hex:   const u8[:],
) -> bool {
    guard out.try_append("Digest username=\"") && append_escaped_digest_param(out, effective_user) else {
        return false;
    }
    guard out.try_append("\", realm=\"") && append_escaped_digest_param(out, realm) else { return false; }
    guard out.try_append("\", nonce=\"") && append_escaped_digest_param(out, nonce) else { return false; }
    guard out.try_append("\", uri=\"") && auth::append_digest_uri(out, uri) else { return false; }
    guard out.try_append("\", algorithm=") && out.try_append(algo) else { return false; }
    guard out.try_append(", response=\"") && append_escaped_digest_param(out, response_hex) else {
        return false;
    }
    return out.try_push('"' as u8);
}

fn resolve_digest_user(
    username: const u8[:],
    realm:    const u8[:],
    userhash: bool,
    algo:     const u8[:],
) -> u8[..128] {
    var effective: u8[..128] = [];
    if userhash {
        let hashed = auth::resolve_userhash(username, realm, algo);
        let _ = effective.try_set(hashed[..]);
        return effective;
    }
    let _ = effective.try_set(username);
    return effective;
}

// Selects preferred RFC 7616 protection quality ("auth" over "auth-int"; empty in legacy RFC 2069 mode).
inline fn resolve_active_qop(raw_qop: const u8[:]) -> const u8[:] {
    guard raw_qop.len > 0 else { return ""; }
    if auth::qop_list_has_token(raw_qop, rfc::DIGEST_QOP_AUTH) {
        return rfc::DIGEST_QOP_AUTH;
    }
    if auth::qop_list_has_token(raw_qop, rfc::DIGEST_QOP_AUTH_INT) {
        return rfc::DIGEST_QOP_AUTH_INT;
    }
    return "";
}
