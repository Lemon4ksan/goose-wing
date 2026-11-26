// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP Digest Access Authentication (RFC 7616) challenge parser, stale sync, and response builder.
namespace auth;

import std;
import core;
import rfc.http;
import .types;
import .internal;
import .digest_core;
import .digest_internal;

// RFC 7616 Section 3.3: The WWW-Authenticate Response Header Field - parses challenge parameters.
//
// Example:
//   raw_header = "Digest realm=\"api\", nonce=\"abcd\", qop=\"auth\""
//   returns: DigestChallenge { realm: "api", valid: true, .. }, ok = true
fn parse_digest_challenge(raw_header: const u8[:]) -> DigestChallenge, bool {
    var chal = DigestChallenge { .. };
    var idx: i64 = 0;
    auth_internal::skip_whitespace_and_commas(raw_header, idx);
    auth_internal::skip_digest_scheme(raw_header, idx);

    var seen_mask: u32            = 0;
    var ext_keys:  u8[..64][..16] = [];
    var need_comma = false;
    while idx < raw_header.len {
        var saw_comma = false;
        while idx < raw_header.len && (core::is_lws(raw_header[idx]) || raw_header[idx] == ',') {
            if raw_header[idx] == ',' { saw_comma = true; }
            idx = core::add_sat_i64(idx, 1);
        }
        if idx >= raw_header.len { break; }
        if need_comma { guard saw_comma else { return DigestChallenge { .. }, false; } }

        let key, ok_k = parse_digest_param_key(raw_header, idx);
        guard ok_k else { return DigestChallenge { .. }, false; }

        var val: u8[..128] = [];
        guard parse_digest_param_val(raw_header, idx, val) else { return DigestChallenge { .. }, false; }
        guard auth_internal::apply_digest_param(chal, key, val[..], seen_mask, ext_keys) else {
            return DigestChallenge { .. }, false;
        }
        need_comma = true;
    }

    guard (seen_mask & 3) == 3 && chal.realm.len > 0 && chal.nonce.len > 0 else {
        return DigestChallenge { .. }, false;
    }
    guard rfc::is_supported_digest_algo(chal.algorithm[..]) else { return DigestChallenge { .. }, false; }
    if chal.qop.len > 0 {
        let has_auth = qop_list_has_token(chal.qop[..], rfc::DIGEST_QOP_AUTH);
        let has_int = qop_list_has_token(chal.qop[..], rfc::DIGEST_QOP_AUTH_INT);
        guard has_auth || has_int else { return DigestChallenge { .. }, false; }
    }
    chal.valid = true;
    return chal, true;
}

// Serializes an HTTP Authorization Digest header value into `out`, escaping quotes and rejecting CRLF.
fn serialize_digest_auth<B>(
    effective_user: const u8[:],
    realm:          const u8[:],
    nonce:          const u8[:],
    uri:            const u8[:],
    algo:           const u8[:],
    response_hex:   const u8[:],
    active_qop:     const u8[:],
    nc_str:         const u8[:],
    cnonce:         const u8[:],
    opaque:         const u8[:],
    userhash:       bool,
    out:            B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    guard effective_user.len > 0 && realm.len > 0 && nonce.len > 0 else { return false; }
    guard uri.len > 0 && rfc::is_supported_digest_algo(algo) else { return false; }
    guard auth_internal::is_ascii_hex_str(response_hex) && (response_hex.len == 32 || response_hex.len == 64) else {
        return false;
    }
    if active_qop.len > 0 {
        let valid_qop = active_qop.eq_ascii_fold(rfc::DIGEST_QOP_AUTH)
            || active_qop.eq_ascii_fold(rfc::DIGEST_QOP_AUTH_INT);
        guard valid_qop && nc_str.len == 8 && auth_internal::is_ascii_hex_str(nc_str) && cnonce.len > 0 else {
            return false;
        }
    }

    out.clear();
    guard auth_internal::serialize_digest_core_kv(out, effective_user, realm, nonce, uri, algo, response_hex) else {
        return false;
    }
    guard auth_internal::serialize_digest_opt_kv(out, active_qop, nc_str, cnonce, opaque, userhash) else {
        return false;
    }
    committed = true;
    return true;
}

// RFC 7616 Section 3.3: Synchronizes stored challenge with incoming `stale=true` nonce and resets `nc` to 1.
fn sync_digest_stale_challenge(
    stored:   DigestChallenge&,
    incoming: const DigestChallenge&,
    creds:    const DigestCredentials&,
    nc:       u32&,
) -> bool {
    guard stored.valid && incoming.valid && incoming.stale else { return false; }
    guard creds.username.len > 0 && incoming.nonce.len > 0 else { return false; }
    if stored.realm.len > 0 && incoming.realm.len > 0 && incoming.realm[..] != stored.realm[..] {
        return false;
    }
    if stored.userhash && !incoming.userhash {
        return false;
    }

    let resolved_algo, algo_ok = auth_internal::resolve_stale_digest_algo(stored.algorithm[..], incoming);
    // RFC 7616 Section 5: Reject stale-challenge qop downgrade from auth-int to auth-only.
    let stored_is_auth_int = auth_internal::resolve_active_qop(stored.qop[..]) == rfc::DIGEST_QOP_AUTH_INT;
    if stored_is_auth_int
        && incoming.qop.len > 0
        && !qop_list_has_token(incoming.qop[..], rfc::DIGEST_QOP_AUTH_INT) {
        return false;
    }
    var next = copy(stored);
    guard algo_ok && next.algorithm.try_set(resolved_algo) else { return false; }
    guard next.nonce.try_set(incoming.nonce[..]) else { return false; }
    guard auth_internal::sync_opt_buf(next.opaque, incoming.opaque[..]) else { return false; }
    guard auth_internal::sync_opt_buf(next.realm, incoming.realm[..]) else { return false; }
    guard auth_internal::sync_opt_buf(next.domain, incoming.domain[..]) else { return false; }
    if stored_is_auth_int {
        guard next.qop.try_set(rfc::DIGEST_QOP_AUTH_INT) else { return false; }
    } else {
        guard auth_internal::sync_opt_buf(next.qop, incoming.qop[..]) else { return false; }
    }
    next.userhash = incoming.userhash;
    next.stale = false;
    next.valid = true;
    stored = copy(next);
    nc = 1;
    return true;
}

// Parses a `WWW-Authenticate` header on 401 retry and updates `stored` + `nc` when `stale=true`.
fn refresh_digest_stale_nonce(
    stored:     DigestChallenge&,
    raw_header: const u8[:],
    creds:      const DigestCredentials&,
    nc:         u32&,
) -> bool {
    let incoming, ok = parse_digest_challenge(raw_header);
    guard ok else { return false; }
    return sync_digest_stale_challenge(stored, incoming, creds, nc);
}

// Computes and serializes an RFC 7616 `Authorization: Digest ...` header value into `out`.
fn compute_digest_response<B>(
    challenge: const DigestChallenge&,
    creds:     const DigestCredentials&,
    method:    const u8[:],
    uri:       const u8[:],
    nc:        u32,
    cnonce:    const u8[:],
    body:      const u8[:],
    out:       B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    guard challenge.valid && creds.username.len > 0 && method.len > 0 && uri.len > 0 else { return false; }
    let active_qop = auth_internal::resolve_active_qop(challenge.qop[..]);
    if challenge.qop.len > 0 {
        guard active_qop.len > 0 && nc >= 1 && cnonce.len > 0 else { return false; }
    } else if rfc::is_sess_digest_algo(challenge.algorithm[..]) {
        guard cnonce.len > 0 else { return false; }
    }

    var nc_str: u8[..16] = [];
    if active_qop.len > 0 {
        core::format_u64_hex_fixed(nc as! u64, 8, nc_str, false);
    }

    var ha1_hex = calculate_digest_ha1(
        challenge.algorithm[..],
        creds.username[..],
        challenge.realm[..],
        creds.password[..],
        challenge.nonce[..],
        cnonce,
    );
    defer core::secure_zeroize_slice(ha1_hex[..]);
    guard ha1_hex.len > 0 else { return false; }

    let is_auth_int = active_qop.eq_ascii_fold(rfc::DIGEST_QOP_AUTH_INT);
    let ha2_hex = calculate_digest_ha2(challenge.algorithm[..], method, uri, is_auth_int, body);
    guard ha2_hex.len > 0 else { return false; }

    let response_hex = calculate_digest_response(
        challenge.algorithm[..],
        ha1_hex[..],
        challenge.nonce[..],
        nc_str[..],
        cnonce,
        active_qop,
        ha2_hex[..],
    );
    guard response_hex.len > 0 else { return false; }

    var effective_user = auth_internal::resolve_digest_user(
        creds.username[..],
        challenge.realm[..],
        challenge.userhash,
        challenge.algorithm[..],
    );
    defer core::secure_zeroize_slice(effective_user[..]);
    guard effective_user.len > 0 else { return false; }

    guard serialize_digest_auth(
        effective_user[..],
        challenge.realm[..],
        challenge.nonce[..],
        uri,
        challenge.algorithm[..],
        response_hex[..],
        active_qop,
        nc_str[..],
        cnonce,
        challenge.opaque[..],
        challenge.userhash,
        out,
    ) else {
        return false;
    }
    committed = true;
    return true;
}
