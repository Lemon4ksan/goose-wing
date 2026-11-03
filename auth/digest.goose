// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7616 HTTP Digest Access Authentication (obsoleting RFC 2617).
// Supports SHA-256 (mandatory by RFC 7616 Section 3.4), SHA-512-256 (high security), and MD5 legacy fallback.
// Handles challenge parsing, HA1/HA2 derivation, qop=auth/auth-int, and Authorization header generation.
namespace wing;

import std;
import core from "..";

// ---- RFC 7616 & RFC 2617 Protocol Constants ------------------------------

const DIGEST_ALGO_MD5:             const u8[:] = "MD5";
const DIGEST_ALGO_MD5_SESS:        const u8[:] = "MD5-sess";
const DIGEST_ALGO_SHA256:          const u8[:] = "SHA-256";
const DIGEST_ALGO_SHA256_SESS:     const u8[:] = "SHA-256-sess";
const DIGEST_ALGO_SHA512_256:      const u8[:] = "SHA-512-256";
const DIGEST_ALGO_SHA512_256_SESS: const u8[:] = "SHA-512-256-sess";

const DIGEST_QOP_AUTH:     const u8[:] = "auth";
const DIGEST_QOP_AUTH_INT: const u8[:] = "auth-int";

// Validates whether the algorithm is officially supported by RFC 7616 / RFC 2617.
inline fn is_supported_digest_algo(algo: const u8[:]) -> bool {
    return eq_ascii_fold(algo, DIGEST_ALGO_MD5)
        || eq_ascii_fold(algo, DIGEST_ALGO_MD5_SESS)
        || eq_ascii_fold(algo, DIGEST_ALGO_SHA256)
        || eq_ascii_fold(algo, DIGEST_ALGO_SHA256_SESS)
        || eq_ascii_fold(algo, DIGEST_ALGO_SHA512_256)
        || eq_ascii_fold(algo, DIGEST_ALGO_SHA512_256_SESS);
}

// ---- Digest Models -------------------------------------------------------

struct DigestChallenge {
    realm:     u8[..128] = [],
    nonce:     u8[..128] = [],
    algorithm: u8[..32]  = "MD5", // RFC 7616 §3.4 default when omitted
    qop:       u8[..32]  = [],    // Empty by default (RFC 2069 legacy mode when omitted)
    opaque:    u8[..128] = [],
    domain:    u8[..128] = [],
    stale:     bool      = false,
    userhash:  bool      = false,
    valid:     bool      = false,
}

struct DigestCredentials {
    username: u8[..128] = [],
    password: u8[..128] = [],
}

// ---- Challenge Parsing (RFC 7616 Section 3.3) -----------------------------

inline fn is_digest_key_char(b: u8) -> bool {
    return b != '=' && b != ' ' && b != '\t' && b != ',' && b != '\r' && b != '\n' && b != '"';
}

// Extracts a digest parameter key up to '=', space, or tab (RFC 7616 §3.3).
// Advances `idx` past the key bytes without consuming the trailing delimiter.
//
// Example:
//   raw = "realm=\"api@example.com\", nonce=\"xyz\"", idx = 0
//   returns: "realm", ok = true, idx = 5 (points to '=')
fn parse_digest_param_key(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    let rem = raw[idx..];
    var k_len: i64 = 0;
    while k_len < rem.len && is_digest_key_char(rem[k_len]) {
        k_len += 1;
    }
    guard k_len > 0 else { return "", false; }
    idx += k_len;
    return rem[..k_len], true;
}

inline fn try_consume_quoted_char<B>(s: const u8[:], pos: i64&, out_val: B&) -> bool {
    let b = s[pos];
    if b == '\\' && pos + 1 < s.len {
        pos += 1;
        guard out_val.try_push(s[pos]) else { return false; }
        pos += 1;
        return true;
    }
    guard out_val.try_push(b) else { return false; }
    pos += 1;
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
            return pos + 1, true;
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
    while n < s.len && !is_digest_token_delim(s[n]) {
        n += 1;
    }
    return n;
}

inline fn commit_digest_param_val<B>(val: const u8[:], out_val: B&) {
    out_val.clear();
    out_val.append(val);
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
    let new_idx = raw.len - rem.len;

    if rem[0] == '"' {
        var tmp: u8[..128] = [];
        let q_consumed, ok = parse_quoted_param(rem, tmp);
        guard ok && tmp.len <= out_val.cap else { return false; }
        commit_digest_param_val(tmp[..], out_val);
        idx = new_idx + q_consumed;
        return true;
    }

    let token_len = scan_digest_token_len(rem);
    guard token_len <= out_val.cap else { return false; }
    commit_digest_param_val(rem[..token_len], out_val);
    idx = new_idx + token_len;
    return true;
}

// Matches and stores core challenge attributes (realm, nonce, algorithm, qop).
fn apply_digest_core_param(chal: DigestChallenge&, key: const u8[:], val: const u8[:]) -> bool {
    if eq_ascii_fold(key, "realm") {
        guard val.len <= chal.realm.cap else { return false; }
        chal.realm.clear();
        chal.realm.append(val);
        return true;
    }
    if eq_ascii_fold(key, "nonce") {
        guard val.len <= chal.nonce.cap else { return false; }
        chal.nonce.clear();
        chal.nonce.append(val);
        return true;
    }
    if eq_ascii_fold(key, "algorithm") {
        guard val.len <= chal.algorithm.cap else { return false; }
        chal.algorithm.clear();
        chal.algorithm.append(val);
        return true;
    }
    if eq_ascii_fold(key, "qop") {
        guard val.len <= chal.qop.cap else { return false; }
        chal.qop.clear();
        chal.qop.append(val);
        return true;
    }
    return false;
}

// Matches and stores optional challenge attributes (opaque, domain, stale, userhash).
fn apply_digest_opt_param(chal: DigestChallenge&, key: const u8[:], val: const u8[:]) {
    if eq_ascii_fold(key, "opaque") {
        guard val.len <= chal.opaque.cap else { return; }
        chal.opaque.clear();
        chal.opaque.append(val);
        return;
    }
    if eq_ascii_fold(key, "domain") {
        guard val.len <= chal.domain.cap else { return; }
        chal.domain.clear();
        chal.domain.append(val);
        return;
    }
    if eq_ascii_fold(key, "stale") {
        chal.stale = eq_ascii_fold(val, "true");
        return;
    }
    if eq_ascii_fold(key, "userhash") {
        chal.userhash = eq_ascii_fold(val, "true");
        return;
    }
}

// Dispatches a challenge parameter key-value pair to core or optional field storage.
fn apply_digest_param(chal: DigestChallenge&, key: const u8[:], val: const u8[:]) {
    if !apply_digest_core_param(chal, key, val) {
        apply_digest_opt_param(chal, key, val);
    }
}

// Advances `idx` past any leading whitespace, commas, or line breaks (RFC 7616 §3.3).
//
// Example:
//   raw = ",  realm=\"api\"", idx = 0
//   advances `idx` to 3 (pointing to 'r')
fn skip_whitespace_and_commas(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..].trim_start_bytes(" \t,\r\n");
    idx = raw.len - rem.len;
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
    idx += 7;
}

// Parses a `WWW-Authenticate: Digest ...` challenge header into structured fields (RFC 7616 §3.3).
//
// Example:
//   raw = "Digest realm=\"api@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""
//   returns: DigestChallenge { realm: "api@example.com", nonce: "dcd98b..." }, ok = true
fn parse_digest_challenge(raw_header: const u8[:]) -> DigestChallenge, bool {
    var chal = DigestChallenge { .. };
    var idx: i64 = 0;

    skip_whitespace_and_commas(raw_header, idx);
    skip_digest_scheme(raw_header, idx);

    while idx < raw_header.len {
        skip_whitespace_and_commas(raw_header, idx);
        guard idx < raw_header.len else { break; }

        let key, key_ok = parse_digest_param_key(raw_header, idx);
        guard key_ok else { return chal, false; }

        var val: u8[..128] = [];
        guard parse_digest_param_val(raw_header, idx, val) else { return chal, false; }

        apply_digest_param(chal, key, val[..]);
    }

    chal.valid = (chal.realm.len > 0 && chal.nonce.len > 0 && is_supported_digest_algo(chal.algorithm[..]));
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
    if eq_ascii_fold(algorithm, DIGEST_ALGO_MD5) || eq_ascii_fold(algorithm, DIGEST_ALGO_MD5_SESS) {
        let md = core::md5(data);
        for b in md {
            core::format_u8_hex(b, out_hex);
        }
    } else if eq_ascii_fold(algorithm, DIGEST_ALGO_SHA512_256)
        || eq_ascii_fold(algorithm, DIGEST_ALGO_SHA512_256_SESS) {
        // RFC 7616 Section 3.9.2: Example with SHA-512-256, Charset, and Userhash - Truncated SHA-512 (first 256 bits) for SHA-512-256 digest calculation.
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
    var a1: u8[..768] = [];
    a1.append(username);
    a1.push(':');
    a1.append(realm);
    a1.push(':');
    a1.append(password);

    var ha1 = digest_hash_hex(algo, a1[..]);

    if eq_ascii_fold(algo, DIGEST_ALGO_SHA256_SESS)
        || eq_ascii_fold(algo, DIGEST_ALGO_MD5_SESS)
        || eq_ascii_fold(algo, DIGEST_ALGO_SHA512_256_SESS) {
        var a1_sess: u8[..512] = [];
        a1_sess.append(ha1[..]);
        a1_sess.push(':');
        a1_sess.append(nonce);
        a1_sess.push(':');
        a1_sess.append(cnonce);
        ha1 = digest_hash_hex(algo, a1_sess[..]);
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
    var a2: u8[..2048] = [];
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
    var a3: u8[..512] = [];
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
// Rejects control characters (\r, \n, \0) and unencoded quotes to prevent header breakout.
fn append_digest_uri<B>(sink: B&, uri: const u8[:]) -> bool {
    for b in uri {
        guard b != '\r' && b != '\n' && b != '\0' && b != '"' else { return false; }
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
    guard sink.len + 17 <= sink.cap else { return false; }
    sink.append("Digest username=\"");
    guard append_escaped_digest_param(sink, effective_user) else { return false; }
    guard sink.len + 10 <= sink.cap else { return false; }
    sink.append("\", realm=\"");
    guard append_escaped_digest_param(sink, realm) else { return false; }
    guard sink.len + 10 <= sink.cap else { return false; }
    sink.append("\", nonce=\"");
    guard append_escaped_digest_param(sink, nonce) else { return false; }
    guard sink.len + 8 <= sink.cap else { return false; }
    sink.append("\", uri=\"");
    guard append_digest_uri(sink, uri) else { return false; }
    guard sink.len + 13 + algo.len + 13 + response_hex.len + 1 <= sink.cap else { return false; }
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
        guard sink.len + 6 + active_qop.len + 5 + nc_str.len + 10 <= sink.cap else { return false; }
        sink.append(", qop=");
        sink.append(active_qop);
        sink.append(", nc=");
        sink.append(nc_str);
        sink.append(", cnonce=\"");
        guard append_escaped_digest_param(sink, cnonce) else { return false; }
        guard sink.len + 1 <= sink.cap else { return false; }
        sink.push('"');
    }

    if opaque.len > 0 {
        guard sink.len + 10 <= sink.cap else { return false; }
        sink.append(", opaque=\"");
        guard append_escaped_digest_param(sink, opaque) else { return false; }
        guard sink.len + 1 <= sink.cap else { return false; }
        sink.push('"');
    }

    if userhash {
        guard sink.len + 16 <= sink.cap else { return false; }
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
    guard ok_core else { return false; }
    let ok_opt = serialize_digest_opt_kv(
        sink,
        active_qop,
        nc_str,
        cnonce,
        opaque,
        userhash,
    );
    guard ok_opt else { return false; }
    return true;
}

fn resolve_userhash(username: const u8[:], realm: const u8[:], algo: const u8[:]) -> u8[..64] {
    var user_realm: u8[..384] = [];
    user_realm.append(username);
    user_realm.push(':');
    user_realm.append(realm);
    return digest_hash_hex(algo, user_realm[..]);
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

inline fn is_qop_token_char(b: u8) -> bool {
    return b != ',' && b != '"' && b != ' ' && b != '\t';
}

// Scans the byte length of a single qop token up to comma, quote, or whitespace (RFC 7616 §3.3).
//
// Example:
//   s = "auth-int, auth"
//   returns: 8 ("auth-int")
fn scan_qop_token_len(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    while n < s.len && is_qop_token_char(s[n]) {
        n += 1;
    }
    return n;
}

fn qop_list_has_token(raw_qop: const u8[:], target: const u8[:]) -> bool {
    var idx: i64 = 0;
    while idx < raw_qop.len {
        let rem = raw_qop[idx..].trim_start_bytes(" \t,\"");
        guard rem.len > 0 else { break; }
        let tok_len = scan_qop_token_len(rem);
        let tok = rem[..tok_len];
        if eq_ascii_fold(tok, target) {
            return true;
        }
        let advance = (raw_qop.len - rem.len) + tok_len;
        idx = advance;
        while idx < raw_qop.len && raw_qop[idx] != ',' {
            idx += 1;
        }
        if idx < raw_qop.len && raw_qop[idx] == ',' {
            idx += 1;
        }
    }
    return false;
}

// Resolves active qop preference from challenge qop parameter (RFC 7616 §3.4).
// Prefers "auth" over "auth-int" if both are offered. Returns empty if neither offered.
//
// Example:
//   raw_qop = "auth, auth-int"
//   returns: "auth"
inline fn resolve_active_qop(raw_qop: const u8[:]) -> const u8[:] {
    guard raw_qop.len > 0 else { return ""; }
    if qop_list_has_token(raw_qop, DIGEST_QOP_AUTH) {
        return DIGEST_QOP_AUTH;
    }
    if qop_list_has_token(raw_qop, DIGEST_QOP_AUTH_INT) {
        return DIGEST_QOP_AUTH_INT;
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
    guard challenge.valid else { return false; }

    let algo = challenge.algorithm[..];
    guard is_supported_digest_algo(algo) else { return false; }

    let active_qop = resolve_active_qop(challenge.qop[..]);
    let is_auth_int = (active_qop.len == 8);

    let effective_user = resolve_digest_user(creds.username[..], challenge.realm[..], challenge.userhash, algo);

    let ha1_hex = calculate_digest_ha1(
        algo,
        creds.username[..],
        challenge.realm[..],
        creds.password[..],
        challenge.nonce[..],
        cnonce,
    );

    let ha2_hex = calculate_digest_ha2(algo, method, uri, is_auth_int, body);

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
