// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7616 HTTP Digest Access Authentication (obsoleting RFC 2617).
// Supports SHA-256 (mandatory by RFC 7616 Section 3.4), SHA-512-256 (high security), and MD5 legacy fallback.
// Handles challenge parsing, HA1/HA2 derivation, qop=auth/auth-int, and Authorization header generation.
namespace wing;

import std;
import core from "..";

// ---- Digest Models -------------------------------------------------------

struct DigestChallenge {
    realm:             u8[..128] = [],
    nonce:             u8[..128] = [],
    algorithm:         u8[..32]  = "MD5", // RFC 7616 §3.4 default when omitted
    qop:               u8[..32]  = [],    // Empty by default (RFC 2069 legacy mode when omitted)
    opaque:            u8[..128] = [],
    domain:            u8[..128] = [],
    stale:             bool      = false,
    userhash:          bool      = false,
    has_explicit_algo: bool      = false,
    valid:             bool      = false,
}

struct DigestCredentials {
    username: u8[..128] = [],
    password: u8[..128] = [],
}

// ---- Challenge Parsing (RFC 7616 Section 3.3) -----------------------------

// Extracts a digest parameter key up to '=', space, or tab (RFC 7616 §3.3).
// Advances `idx` past the key bytes without consuming the trailing delimiter.
//
// Example:
//   raw = "realm=\"api@example.com\", nonce=\"xyz\"", idx = 0
//   returns: "realm", ok = true, idx = 5 (points to '=')
fn parse_digest_param_key(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    let rem = raw[idx..];
    var k_len: i64 = 0;
    while k_len < rem.len && core::is_tchar(rem[k_len]) {
        k_len = core::add_sat_i64(k_len, 1);
    }
    guard k_len > 0 else { return "", false; }
    if k_len < rem.len {
        let next_b = rem[k_len];
        guard next_b == '=' || next_b == ' ' || next_b == '\t' else { return "", false; }
    }
    idx = core::add_sat_i64(idx, k_len);
    return rem[..k_len], true;
}

inline fn is_valid_quoted_digest_byte(b: u8) -> bool {
    return core::is_ascii_printable(b) || b >= 0x80;
}

// Consumes one quoted-pair or unescaped character at `pos` into `out_val`.
//
// Example:
//   s = "\"\\a\"", pos = 1
//   returns: ok = true, pos = 3, out_val = "a"
inline fn try_consume_quoted_char<B>(s: const u8[:], pos: i64&, out_val: B&) -> bool {
    let b = s[pos];
    let next_pos = core::add_sat_i64(pos, 1);
    if b == '\\' && next_pos < s.len {
        let esc = s[next_pos];
        guard is_valid_quoted_digest_byte(esc) && out_val.try_push(esc) else { return false; }
        pos = core::add_sat_i64(next_pos, 1);
        return true;
    }
    guard b != '\\' && is_valid_quoted_digest_byte(b) && out_val.try_push(b) else { return false; }
    pos = next_pos;
    return true;
}

// Parses a quoted string parameter up to the unescaped closing quote (RFC 7616 §3.4).
// Assumes s begins with the opening quote ('"'). Unescapes backslash sequences.
//
// Example:
//   s = "\"hello \\\"world\\\"\", next=1"
//   returns: consumed = 17, ok = true, out_val = "hello \"world\""
fn parse_quoted_param<B>(s: const u8[:], out_val: B&) -> i64, bool {
    var pos: i64 = 1;
    while pos < s.len {
        if s[pos] == '"' {
            return core::add_sat_i64(pos, 1), true;
        }
        guard try_consume_quoted_char(s, pos, out_val) else { return 0, false; }
    }
    return 0, false;
}

inline fn is_digest_token_delim(b: u8) -> bool {
    return b == ' ' || b == '\t' || b == ',' || b == '\r' || b == '\n';
}

// Scans an unquoted digest token length up to whitespace, comma, or newline (RFC 7616 §3.3).
//
// Example:
//   s = "token123, next=val"
//   returns: 8 (length of "token123")
inline fn scan_digest_token_len(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    while n < s.len && !is_digest_token_delim(s[n]) && core::is_tchar(s[n]) {
        n = core::add_sat_i64(n, 1);
    }
    return n;
}

// Parses a parameter value, which can be quoted ("value") or an unquoted token (RFC 7616 §3.3).
// Advances `idx` past the parsed value on success.
//
// Example:
//   raw = "=\"secret\", other=1", idx = 0
//   returns: ok = true, idx = 9, out_val = "secret"
fn parse_digest_param_val<B>(raw: const u8[:], idx: i64&, out_val: B&) -> bool {
    let rem_pre = raw[idx..].trim_start_bytes(" \t");
    guard rem_pre.len > 0 && rem_pre[0] == '=' else { return false; }
    let rem = rem_pre[1..].trim_start_bytes(" \t");
    guard rem.len > 0 else { return false; }
    let new_idx = core::sub_sat_i64(raw.len, rem.len);

    if rem[0] == '"' {
        var tmp: u8[..128] = [];
        let q_consumed, ok = parse_quoted_param(rem, tmp);
        let after_q = core::add_sat_i64(new_idx, q_consumed);
        let delim_ok = after_q >= raw.len || is_digest_token_delim(raw[after_q]);
        guard ok && delim_ok && out_val.try_set(tmp[..]) else { return false; }
        idx = after_q;
        return true;
    }

    let token_len = scan_digest_token_len(rem);
    let after_tok = core::add_sat_i64(new_idx, token_len);
    let tok_delim_ok = after_tok >= raw.len || is_digest_token_delim(raw[after_tok]);
    guard token_len > 0 && tok_delim_ok && out_val.try_set(rem[..token_len]) else { return false; }
    idx = after_tok;
    return true;
}

inline fn try_mark_digest_param(seen_mask: u32&, bit: u32) -> bool {
    guard (seen_mask & bit) == 0 else { return false; }
    seen_mask = seen_mask | bit;
    return true;
}

// Matches and stores core challenge attributes (realm, nonce, algorithm, qop).
// Returns (handled: bool, ok: bool).
fn apply_digest_core_param(
    chal:      DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
) -> bool, bool {
    if eq_ascii_fold(key, "realm") {
        return true, try_mark_digest_param(seen_mask, 1) && chal.realm.try_set(val);
    }
    if eq_ascii_fold(key, "nonce") {
        return true, try_mark_digest_param(seen_mask, 2) && chal.nonce.try_set(val);
    }
    if eq_ascii_fold(key, "algorithm") {
        chal.has_explicit_algo = true;
        return true, try_mark_digest_param(seen_mask, 4) && chal.algorithm.try_set(val);
    }
    if eq_ascii_fold(key, "qop") {
        return true, try_mark_digest_param(seen_mask, 8) && val.len > 0 && chal.qop.try_set(val);
    }
    return false, true;
}

// Matches and stores optional challenge attributes (opaque, domain, stale, userhash, charset).
fn apply_digest_opt_param(
    chal:      DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
) -> bool {
    if eq_ascii_fold(key, "opaque") {
        return try_mark_digest_param(seen_mask, 16) && chal.opaque.try_set(val);
    }
    if eq_ascii_fold(key, "domain") {
        return try_mark_digest_param(seen_mask, 32) && chal.domain.try_set(val);
    }
    if eq_ascii_fold(key, "stale") {
        guard try_mark_digest_param(seen_mask, 64) else { return false; }
        chal.stale = eq_ascii_fold(val, "true");
        return true;
    }
    if eq_ascii_fold(key, "userhash") {
        let is_true = eq_ascii_fold(val, "true");
        guard try_mark_digest_param(seen_mask, 128) && (is_true || eq_ascii_fold(val, "false")) else { return false; }
        chal.userhash = is_true;
        return true;
    }
    if eq_ascii_fold(key, "charset") {
        return try_mark_digest_param(seen_mask, 256) && eq_ascii_fold(val, "UTF-8");
    }
    return true;
}

// Dispatches a challenge parameter key-value pair to core or optional field storage.
fn apply_digest_param(
    chal:      DigestChallenge&,
    key:       const u8[:],
    val:       const u8[:],
    seen_mask: u32&,
) -> bool {
    let handled, ok_core = apply_digest_core_param(chal, key, val, seen_mask);
    if handled {
        return ok_core;
    }
    return apply_digest_opt_param(chal, key, val, seen_mask);
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
    guard rem.len >= 7 && eq_ascii_fold(rem[..6], "digest") else { return; }
    guard rem[6] == ' ' || rem[6] == '\t' else { return; }
    idx = core::add_sat_i64(idx, 7);
}

// Parses a `WWW-Authenticate: Digest ...` challenge header into structured fields (RFC 7616 §3.3).
//
// Example:
//   raw = "Digest realm=\"api@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""
//   returns: DigestChallenge { realm: "api@example.com", nonce: "dcd98b..." }, ok = true
fn parse_digest_challenge(raw_header: const u8[:]) -> DigestChallenge, bool {
    var chal = DigestChallenge { .. };
    var idx:       i64 = 0;
    var seen_mask: u32 = 0;

    skip_whitespace_and_commas(raw_header, idx);
    skip_digest_scheme(raw_header, idx);

    while idx < raw_header.len {
        skip_whitespace_and_commas(raw_header, idx);
        guard idx < raw_header.len else { break; }

        let key, key_ok = parse_digest_param_key(raw_header, idx);
        guard key_ok else { return DigestChallenge { .. }, false; }

        var val: u8[..128] = [];
        guard parse_digest_param_val(raw_header, idx, val) else { return DigestChallenge { .. }, false; }

        guard apply_digest_param(chal, key, val[..], seen_mask) else { return DigestChallenge { .. }, false; }
    }

    chal.valid = (chal.realm.len > 0 && chal.nonce.len > 0 && rfc::is_supported_digest_algo(chal.algorithm[..]));
    return chal, chal.valid;
}

// ---- Digest Calculation (RFC 7616 Section 3.4 & 3.5) ---------------------

// Computes MD5, SHA-256, or SHA-512-256 digest and returns formatted hexadecimal string.
//
// Example:
//   algorithm = "SHA-256", data = "hello"
//   returns: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
fn digest_hash_hex(algorithm: const u8[:], data: const u8[:]) -> u8[..64] {
    var out_hex: u8[..64] = [];
    if eq_ascii_fold(algorithm, rfc::DIGEST_ALGO_MD5) || eq_ascii_fold(algorithm, rfc::DIGEST_ALGO_MD5_SESS) {
        let md = core::md5(data);
        for b in md {
            core::format_u8_hex(b, out_hex);
        }
    } else if eq_ascii_fold(algorithm, rfc::DIGEST_ALGO_SHA512_256)
        || eq_ascii_fold(algorithm, rfc::DIGEST_ALGO_SHA512_256_SESS) {
        // RFC 7616 Section 3.9.2: Example with SHA-512-256, Charset, and Userhash (first 256 bits of SHA-512).
        let sh = core::sha512(data);
        for i in 32 {
            core::format_u8_hex(sh[i], out_hex);
        }
    } else {
        // Default to SHA-256 (RFC 7616 standard)
        let sh = core::sha256(data);
        for b in sh {
            core::format_u8_hex(b, out_hex);
        }
    }
    return out_hex;
}

// Calculates RFC 7616 HA1 hash string from user credentials.
//
// Example:
//   algo = "SHA-256", username = "Mufasa", realm = "myrealm", password = "SecretPassword"
//   returns: "66b23d060da48775017ec881db093beec3b1028307e3210250052b4111421008"
fn calculate_digest_ha1(
    algo:     const u8[:],
    username: const u8[:],
    realm:    const u8[:],
    password: const u8[:],
    nonce:    const u8[:],
    cnonce:   const u8[:],
) -> u8[..64] {
    var a1:        u8[..768] = [];
    var empty_res: u8[..64]  = [];
    guard username.len > 0 && realm.len > 0 else { return empty_res; }
    let need1 = core::add_sat_i64(core::add_sat_i64(username.len, realm.len), password.len);
    guard core::add_sat_i64(need1, 2) <= a1.cap else { return empty_res; }
    a1.append(username);
    a1.push(':');
    a1.append(realm);
    a1.push(':');
    a1.append(password);

    var ha1 = digest_hash_hex(algo, a1[..]);
    core::secure_zeroize_slice(a1[..]);

    if rfc::is_sess_digest_algo(algo) {
        guard nonce.len > 0 && cnonce.len > 0 else { return empty_res; }
        var a1_sess: u8[..512] = [];
        let need_sess = core::add_sat_i64(core::add_sat_i64(ha1.len, nonce.len), cnonce.len);
        guard core::add_sat_i64(need_sess, 2) <= a1_sess.cap else { return empty_res; }
        a1_sess.append(ha1[..]);
        a1_sess.push(':');
        a1_sess.append(nonce);
        a1_sess.push(':');
        a1_sess.append(cnonce);
        ha1 = digest_hash_hex(algo, a1_sess[..]);
        core::secure_zeroize_slice(a1_sess[..]);
    }
    return ha1;
}

// Calculates RFC 7616 HA2 hash string from HTTP request attributes.
//
// Example:
//   algo = "SHA-256", method = "GET", uri = "/dir/index.html", is_auth_int = false, body = ""
//   returns: "39f363da7850af35b22440f6f8493fb60822d0bceb67218c51e37d9c53bc4e0e"
fn calculate_digest_ha2(
    algo:        const u8[:],
    method:      const u8[:],
    uri:         const u8[:],
    is_auth_int: bool,
    body:        const u8[:],
) -> u8[..64] {
    var a2:        u8[..2048] = [];
    var empty_res: u8[..64]   = [];
    guard method.len > 0 && uri.len > 0 else { return empty_res; }
    let extra: i64 = if is_auth_int { 65 } else { 0 };
    let need2 = core::add_sat_i64(core::add_sat_i64(method.len, uri.len), extra);
    guard core::add_sat_i64(need2, 1) <= a2.cap else { return empty_res; }
    a2.append(method);
    a2.push(':');
    a2.append(uri);

    if is_auth_int {
        let h_body_hex = digest_hash_hex(algo, body);
        a2.push(':');
        a2.append(h_body_hex[..]);
    }

    return digest_hash_hex(algo, a2[..]);
}

// Calculates RFC 7616 final response hash string from HA1, HA2, and nonce values.
//
// Example:
//   algo = "SHA-256", ha1_hex = "66b2...", nonce = "xyz", nc_str = "00000001", ...
//   returns: "86049f1f1000e540362c603f50b9cf140d0371f68682d4577da4e0610a29ea83"
fn calculate_digest_response(
    algo:       const u8[:],
    ha1_hex:    const u8[:],
    nonce:      const u8[:],
    nc_str:     const u8[:],
    cnonce:     const u8[:],
    active_qop: const u8[:],
    ha2_hex:    const u8[:],
) -> u8[..64] {
    var a3:        u8[..1024] = [];
    var empty_res: u8[..64]   = [];
    guard ha1_hex.len > 0 && ha2_hex.len > 0 && nonce.len > 0 else { return empty_res; }
    if active_qop.len > 0 {
        guard nc_str.len > 0 && cnonce.len > 0 else { return empty_res; }
    }
    let qop_extra: i64 = if active_qop.len > 0 {
        core::add_sat_i64(core::add_sat_i64(nc_str.len, cnonce.len), core::add_sat_i64(active_qop.len, 3))
    } else {
        0
    };
    let need3 = core::add_sat_i64(
        core::add_sat_i64(ha1_hex.len, nonce.len),
        core::add_sat_i64(ha2_hex.len, core::add_sat_i64(qop_extra, 2)),
    );
    guard need3 <= a3.cap else { return empty_res; }

    a3.append(ha1_hex);
    a3.push(':');
    a3.append(nonce);

    if active_qop.len > 0 {
        a3.push(':');
        a3.append(nc_str);
        a3.push(':');
        a3.append(cnonce);
        a3.push(':');
        a3.append(active_qop);
    }

    a3.push(':');
    a3.append(ha2_hex);

    return digest_hash_hex(algo, a3[..]);
}

// Appends a parameter value while escaping quotes and backslashes (RFC 7616 §3.4).
// Rejects control characters (\r, \n, \0).
//
// Example:
//   val = "hello \"world\""
//   appends: "hello \\\"world\\\"" to `sink`, returns: true
fn append_escaped_digest_param<B>(sink: B&, val: const u8[:]) -> bool {
    for b in val {
        guard b != '\r' && b != '\n' && b != 0 else { return false; }
        if b == '"' || b == '\\' {
            guard sink.len < sink.cap else { return false; }
            sink.push('\\');
        }
        guard sink.len < sink.cap else { return false; }
        sink.push(b);
    }
    return true;
}

// Appends a digest URI without backslash escaping (RFC 7616 §3.4 / RFC 3986).
// Rejects control characters (\r, \n, \0), backslashes, and unencoded quotes to prevent header breakout.
fn append_digest_uri<B>(sink: B&, uri: const u8[:]) -> bool {
    for b in uri {
        guard b != '\r' && b != '\n' && b != '\0' && b != '"' && b != '\\' else { return false; }
        guard sink.len < sink.cap else { return false; }
        sink.push(b);
    }
    return true;
}

// Appends mandatory RFC 7616 Digest key-value pairs (username, realm, nonce, uri, response).
fn serialize_digest_core_kv<B>(
    sink:           B&,
    effective_user: const u8[:],
    realm:          const u8[:],
    nonce:          const u8[:],
    uri:            const u8[:],
    algo:           const u8[:],
    response_hex:   const u8[:],
) -> bool {
    guard effective_user.len > 0 && realm.len > 0 && nonce.len > 0 && uri.len > 0 && response_hex.len > 0 else {
        return false;
    }
    guard core::add_sat_i64(sink.len, 17) <= sink.cap else { return false; }
    sink.append("Digest username=\"");
    guard append_escaped_digest_param(sink, effective_user) else { return false; }
    guard core::add_sat_i64(sink.len, 10) <= sink.cap else { return false; }
    sink.append("\", realm=\"");
    guard append_escaped_digest_param(sink, realm) else { return false; }
    guard core::add_sat_i64(sink.len, 10) <= sink.cap else { return false; }
    sink.append("\", nonce=\"");
    guard append_escaped_digest_param(sink, nonce) else { return false; }
    guard core::add_sat_i64(sink.len, 8) <= sink.cap else { return false; }
    sink.append("\", uri=\"");
    guard append_digest_uri(sink, uri) else { return false; }
    let tail_need = core::add_sat_i64(core::add_sat_i64(algo.len, response_hex.len), 27);
    guard core::add_sat_i64(sink.len, tail_need) <= sink.cap else { return false; }
    sink.append("\", algorithm=");
    sink.append(algo);
    sink.append(", response=\"");
    sink.append(response_hex);
    sink.append("\"");
    return true;
}

// Appends optional RFC 7616 Digest key-value pairs (qop, nc, cnonce, opaque, userhash).
fn serialize_digest_opt_kv<B>(
    sink:       B&,
    active_qop: const u8[:],
    nc_str:     const u8[:],
    cnonce:     const u8[:],
    opaque:     const u8[:],
    userhash:   bool,
) -> bool {
    if active_qop.len > 0 {
        let qop_need = core::add_sat_i64(core::add_sat_i64(active_qop.len, nc_str.len), 21);
        guard core::add_sat_i64(sink.len, qop_need) <= sink.cap else { return false; }
        sink.append(", qop=");
        sink.append(active_qop);
        sink.append(", nc=");
        sink.append(nc_str);
        sink.append(", cnonce=\"");
        guard append_escaped_digest_param(sink, cnonce) else { return false; }
        guard core::add_sat_i64(sink.len, 1) <= sink.cap else { return false; }
        sink.push('"');
    } else if cnonce.len > 0 {
        guard core::add_sat_i64(sink.len, 11) <= sink.cap else { return false; }
        sink.append(", cnonce=\"");
        guard append_escaped_digest_param(sink, cnonce) else { return false; }
        guard core::add_sat_i64(sink.len, 1) <= sink.cap else { return false; }
        sink.push('"');
    }

    if opaque.len > 0 {
        guard core::add_sat_i64(sink.len, 10) <= sink.cap else { return false; }
        sink.append(", opaque=\"");
        guard append_escaped_digest_param(sink, opaque) else { return false; }
        guard core::add_sat_i64(sink.len, 1) <= sink.cap else { return false; }
        sink.push('"');
    }

    if userhash {
        guard core::add_sat_i64(sink.len, 16) <= sink.cap else { return false; }
        sink.append(", userhash=true");
    }

    return true;
}

// Serializes an RFC 7616 Authorization header value into output buffer.
//
// Example:
//   effective_user = "Mufasa", realm = "myrealm", nonce = "xyz", ...
//   returns: true, out_header = "Digest username=\"Mufasa\", realm=\"myrealm\", ..."
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
    sink:           B&,
) -> bool {
    sink.clear();
    let ok_core = serialize_digest_core_kv(
        sink,
        effective_user,
        realm,
        nonce,
        uri,
        algo,
        response_hex,
    );
    guard ok_core else {
        sink.clear();
        return false;
    }
    let ok_opt = serialize_digest_opt_kv(
        sink,
        active_qop,
        nc_str,
        cnonce,
        opaque,
        userhash,
    );
    guard ok_opt else {
        sink.clear();
        return false;
    }
    return true;
}

fn resolve_userhash(username: const u8[:], realm: const u8[:], algo: const u8[:]) -> u8[..64] {
    var user_realm: u8[..512] = [];
    var empty_res:  u8[..64]  = [];
    let need = core::add_sat_i64(core::add_sat_i64(username.len, realm.len), 1);
    guard need <= user_realm.cap else { return empty_res; }
    user_realm.append(username);
    user_realm.push(':');
    user_realm.append(realm);
    let res = digest_hash_hex(algo, user_realm[..]);
    core::secure_zeroize_slice(user_realm[..]);
    return res;
}

fn resolve_digest_user(
    username: const u8[:],
    realm:    const u8[:],
    userhash: bool,
    algo:     const u8[:],
) -> u8[..128] {
    if userhash {
        let h = resolve_userhash(username, realm, algo);
        var out: u8[..128] = [];
        for b in h { out.push(b); }
        return out;
    }
    var out_user: u8[..128] = [];
    guard username.len <= out_user.cap else { return out_user; }
    out_user.append(username);
    return out_user;
}

// Scans the byte length of a single qop token up to comma, quote, or whitespace (RFC 7616 §3.3).
//
// Example:
//   s = "auth-int, auth"
//   returns: 8 ("auth-int")
fn scan_qop_token_len(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    while n < s.len && core::is_tchar(s[n]) {
        n = core::add_sat_i64(n, 1);
    }
    return n;
}

fn qop_list_has_token(raw_qop: const u8[:], target: const u8[:]) -> bool {
    var idx:   i64  = 0;
    var found: bool = false;
    while idx < raw_qop.len {
        let rem = raw_qop[idx..].trim_start_bytes(" \t,\"");
        guard rem.len > 0 else { break; }
        let tok_len = scan_qop_token_len(rem);
        guard tok_len > 0 else { return false; }
        let tok = rem[..tok_len];
        let after_tok = rem[tok_len..].trim_start_bytes(" \t\"");
        guard after_tok.len == 0 || after_tok[0] == ',' else { return false; }
        if eq_ascii_fold(tok, target) {
            found = true;
        }
        idx = core::sub_sat_i64(raw_qop.len, after_tok.len);
        if idx < raw_qop.len && raw_qop[idx] == ',' {
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return found;
}

// Synchronizes an optional challenge buffer: preserves destination when source is empty,
// or overwrites with source when non-empty (RFC 7616 §3.3).
inline fn sync_opt_buf<B>(dst: B&, src: const u8[:]) -> bool {
    guard src.len > 0 else { return true; }
    return dst.try_set(src);
}

inline fn is_md5_digest_algo(algo: const u8[:]) -> bool {
    return eq_ascii_fold(algo, rfc::DIGEST_ALGO_MD5) || eq_ascii_fold(algo, rfc::DIGEST_ALGO_MD5_SESS);
}

inline fn resolve_stale_digest_algo(stored_algo: const u8[:], incoming: const DigestChallenge&) -> const u8[:], bool {
    let is_implicit_md5 = !incoming.has_explicit_algo && eq_ascii_fold(incoming.algorithm[..], rfc::DIGEST_ALGO_MD5);
    if is_implicit_md5 && stored_algo.len > 0 {
        return stored_algo, rfc::is_supported_digest_algo(stored_algo);
    }
    guard rfc::is_supported_digest_algo(incoming.algorithm[..]) else { return "", false; }
    if stored_algo.len > 0 && !is_md5_digest_algo(stored_algo) && is_md5_digest_algo(incoming.algorithm[..]) {
        return "", false;
    }
    return incoming.algorithm[..], true;
}

// Synchronizes stored Digest challenge state when an upstream 401 response includes `stale=true`
// (RFC 7616 Section 3.3 / vendor/curl vauth/digest.c).
// Refreshes the stored `nonce` (and `opaque` if present in `incoming`) and resets the nonce
// counter `nc` to `1` so the request can be retried automatically without user re-authentication.
// Returns `false` if `incoming` is invalid, `incoming.stale` is `false`, or credentials are empty.
//
// Example:
//   incoming = DigestChallenge { nonce: "new_nonce_99", stale: true, valid: true }, nc = 5
//   returns: true, stored.nonce = "new_nonce_99", nc = 1
fn sync_digest_stale_challenge(
    stored:   DigestChallenge&,
    incoming: const DigestChallenge&,
    creds:    const DigestCredentials&,
    nc:       u32&,
) -> bool {
    guard stored.valid && incoming.valid && incoming.stale && creds.username.len > 0 else { return false; }
    let eff_algo, algo_ok = resolve_stale_digest_algo(stored.algorithm[..], incoming);
    var next = copy(stored);
    guard incoming.nonce.len > 0 && next.nonce.try_set(incoming.nonce[..]) && algo_ok else { return false; }
    guard next.algorithm.try_set(eff_algo) && sync_opt_buf(next.opaque, incoming.opaque[..]) else { return false; }
    guard sync_opt_buf(next.realm, incoming.realm[..]) else { return false; }
    guard sync_opt_buf(next.qop, incoming.qop[..]) else { return false; }
    guard sync_opt_buf(next.domain, incoming.domain[..]) else { return false; }
    next.userhash = incoming.userhash;
    next.stale = false;
    next.valid = true;
    stored = copy(next);
    nc = 1;
    return true;
}

// Parses a `WWW-Authenticate: Digest` header and synchronizes `stored` + `nc = 1` if `stale=true`.
//
// Example:
//   raw_header = "Digest realm=\"api\", nonce=\"fresh123\", stale=true", nc = 4
//   returns: true, stored.nonce = "fresh123", nc = 1
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

// Resolves active qop preference from challenge qop parameter (RFC 7616 §3.4).
// Prefers "auth" over "auth-int" if both are offered. Returns empty if neither offered.
//
// Example:
//   raw_qop = "auth, auth-int"
//   returns: "auth"
inline fn resolve_active_qop(raw_qop: const u8[:]) -> const u8[:] {
    guard raw_qop.len > 0 else { return ""; }
    if qop_list_has_token(raw_qop, rfc::DIGEST_QOP_AUTH) {
        return rfc::DIGEST_QOP_AUTH;
    }
    if qop_list_has_token(raw_qop, rfc::DIGEST_QOP_AUTH_INT) {
        return rfc::DIGEST_QOP_AUTH_INT;
    }
    return "";
}

// Computes RFC 7616 Digest response and outputs the full Authorization header.
//
// Example:
//   challenge = { realm: "test", nonce: "abc", algorithm: "SHA-256" }, creds = { username: "user", password: "pwd" }
//   returns: true, out_header = "Digest username=\"user\", realm=\"test\", ..."
fn compute_digest_response<B>(
    challenge:  const DigestChallenge&,
    creds:      const DigestCredentials&,
    method:     const u8[:],
    uri:        const u8[:],
    nc:         u32,
    cnonce:     const u8[:],
    body:       const u8[:],
    out_header: B&,
) -> bool {
    guard challenge.valid && creds.username.len > 0 else { return false; }

    let algo = challenge.algorithm[..];
    guard rfc::is_supported_digest_algo(algo) else { return false; }

    let active_qop = resolve_active_qop(challenge.qop[..]);
    guard challenge.qop.len == 0 || active_qop.len > 0 else { return false; }
    let is_auth_int = eq_ascii_fold(active_qop, rfc::DIGEST_QOP_AUTH_INT);

    let is_sess = rfc::is_sess_digest_algo(algo);
    if active_qop.len > 0 || is_sess {
        guard cnonce.len > 0 else { return false; }
    }
    if active_qop.len > 0 {
        guard nc > 0 else { return false; }
    }

    let effective_user = resolve_digest_user(creds.username[..], challenge.realm[..], challenge.userhash, algo);
    guard effective_user.len > 0 else { return false; }

    let ha1_hex = calculate_digest_ha1(
        algo,
        creds.username[..],
        challenge.realm[..],
        creds.password[..],
        challenge.nonce[..],
        cnonce,
    );

    let ha2_hex = calculate_digest_ha2(algo, method, uri, is_auth_int, body);
    guard ha1_hex.len > 0 && ha2_hex.len > 0 else { return false; }

    var nc_str: u8[..16] = [];
    core::format_u64_hex_fixed(nc, 8, nc_str, false);

    let response_hex = calculate_digest_response(
        algo,
        ha1_hex[..],
        challenge.nonce[..],
        nc_str[..],
        cnonce,
        active_qop,
        ha2_hex[..],
    );
    guard response_hex.len > 0 else { return false; }

    return serialize_digest_auth(
        effective_user[..],
        challenge.realm[..],
        challenge.nonce[..],
        uri,
        algo,
        response_hex[..],
        active_qop,
        nc_str[..],
        cnonce,
        challenge.opaque[..],
        challenge.userhash,
        out_header,
    );
}
