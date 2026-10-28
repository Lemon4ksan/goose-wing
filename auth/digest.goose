// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7616 HTTP Digest Access Authentication (obsoleting RFC 2617).
// Supports SHA-256 (mandatory by RFC 7616 Section 3.4) and MD5 legacy fallback.
// Handles challenge parsing, HA1/HA2 derivation, qop=auth/auth-int, and Authorization header generation.
namespace wing;

import std;
import core from "..";

// ---- 1. Digest Models -------------------------------------------------------

struct DigestChallenge {
    realm: u8[..128] = [],
    nonce: u8[..128] = [],
    algorithm: u8[..32] = "SHA-256",
    qop: u8[..32] = "auth",
    opaque: u8[..128] = [],
    domain: u8[..128] = [],
    stale: bool = false,
    userhash: bool = false,
    valid: bool = false,
}

struct DigestCredentials {
    username: u8[..128] = [],
    password: u8[..128] = [],
}

// ---- 2. Challenge Parsing (RFC 7616 Section 3.3) -----------------------------

fn skip_whitespace_and_commas(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..].trim_start_bytes(" \t,\r\n");
    idx = raw.len - rem.len;
}

fn parse_digest_param_key(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    let rem = raw[idx..];
    var k_len: i64 = 0;
    while k_len < rem.len && rem[k_len] != '=' && rem[k_len] != ' ' && rem[k_len] != '\t' {
        k_len += 1;
    }
    guard k_len > 0 else { return "", false; }
    idx += k_len;
    return rem[..k_len], true;
}

fn parse_quoted_param<B>(s: const u8[:], out_val: B&) -> i64, bool {
    var pos: i64 = 1;
    while pos < s.len {
        let b = s[pos];
        if b == '"' {
            return pos + 1, true;
        }
        if b == '\\' && pos + 1 < s.len {
            pos += 1;
            guard out_val.try_push(s[pos]) else { return 0, false; }
            pos += 1;
            continue;
        }
        guard out_val.try_push(b) else { return 0, false; }
        pos += 1;
    }
    return 0, false;
}

fn parse_digest_param_val<B>(raw: const u8[:], idx: i64&, out_val: B&) -> bool {
    let rem = raw[idx..].trim_start_bytes(" \t=");
    guard rem.len > 0 else { return false; }
    let new_idx = raw.len - rem.len;

    if rem[0] == '"' {
        var tmp: u8[..128] = [];
        let consumed, ok = parse_quoted_param(rem, tmp);
        guard ok else { return false; }
        out_val.clear();
        out_val.append(tmp[..]);
        idx = new_idx + consumed;
        return true;
    }

    var token_len: i64 = 0;
    while token_len < rem.len && !core::contains_byte(" \t,\r\n", rem[token_len]) {
        token_len += 1;
    }
    guard token_len <= out_val.cap else { return false; }
    out_val.clear();
    out_val.append(rem[..token_len]);
    idx = new_idx + token_len;
    return true;
}

fn apply_digest_core_param(chal: DigestChallenge&, key: const u8[:], val: const u8[:]) -> bool {
    if eq_ascii_fold(key, "realm") { chal.realm.clear(); chal.realm.append(val); return true; }
    if eq_ascii_fold(key, "nonce") { chal.nonce.clear(); chal.nonce.append(val); return true; }
    if eq_ascii_fold(key, "algorithm") { chal.algorithm.clear(); chal.algorithm.append(val); return true; }
    if eq_ascii_fold(key, "qop") { chal.qop.clear(); chal.qop.append(val); return true; }
    return false;
}

fn apply_digest_opt_param(chal: DigestChallenge&, key: const u8[:], val: const u8[:]) {
    if eq_ascii_fold(key, "opaque") { chal.opaque.clear(); chal.opaque.append(val); return; }
    if eq_ascii_fold(key, "domain") { chal.domain.clear(); chal.domain.append(val); return; }
    if eq_ascii_fold(key, "stale") { chal.stale = eq_ascii_fold(val, "true"); return; }
    if eq_ascii_fold(key, "userhash") { chal.userhash = eq_ascii_fold(val, "true"); return; }
}

fn apply_digest_param(chal: DigestChallenge&, key: const u8[:], val: const u8[:]) {
    if !apply_digest_core_param(chal, key, val) {
        apply_digest_opt_param(chal, key, val);
    }
}

// Parses a `WWW-Authenticate: Digest ...` challenge header into structured fields
fn parse_digest_challenge(raw_header: const u8[:]) -> DigestChallenge, bool {
    var chal = DigestChallenge { .. };
    var idx: i64 = 0;

    // Optional leading scheme "Digest "
    skip_whitespace_and_commas(raw_header, idx);
    let rem_scheme = raw_header[idx..];
    if rem_scheme.len >= 7 && eq_ascii_fold(rem_scheme[..6], "digest") && (rem_scheme[6] == ' ' || rem_scheme[6] == '\t') {
        idx += 7;
    }

    while idx < raw_header.len {
        skip_whitespace_and_commas(raw_header, idx);
        guard idx < raw_header.len else { break; }

        let key, key_ok = parse_digest_param_key(raw_header, idx);
        guard key_ok else { return chal, false; }

        var val: u8[..128] = [];
        guard parse_digest_param_val(raw_header, idx, val) else { return chal, false; }

        apply_digest_param(chal, key, val[..]);
    }

    chal.valid = (chal.realm.len > 0 && chal.nonce.len > 0);
    return chal, chal.valid;
}

// ---- 3. Digest Calculation (RFC 7616 Section 3.4 & 3.5) ---------------------

fn digest_hash_hex<B>(algorithm: const u8[:], data: const u8[:], out_hex: B&) {
    out_hex.clear();
    if eq_ascii_fold(algorithm, "md5") || eq_ascii_fold(algorithm, "md5-sess") {
        let md = core::md5(data);
        for b in md {
            core::format_u8_hex(b, out_hex);
        }
    } else {
        // Default to SHA-256 (RFC 7616 standard)
        let sh = core::sha256(data);
        for b in sh {
            core::format_u8_hex(b, out_hex);
        }
    }
}

fn calculate_digest_ha1(
    algo: const u8[:],
    username: const u8[:],
    realm: const u8[:],
    password: const u8[:],
    nonce: const u8[:],
    cnonce: const u8[:],
    out_ha1_hex: u8[..64]&,
) {
    var a1: u8[>..] = [];
    a1.append(username);
    a1.push(':');
    a1.append(realm);
    a1.push(':');
    a1.append(password);

    digest_hash_hex(algo, a1[..], out_ha1_hex);

    if eq_ascii_fold(algo, "sha-256-sess") || eq_ascii_fold(algo, "md5-sess") {
        var a1_sess: u8[>..] = [];
        a1_sess.append(out_ha1_hex[..]);
        a1_sess.push(':');
        a1_sess.append(nonce);
        a1_sess.push(':');
        a1_sess.append(cnonce);
        digest_hash_hex(algo, a1_sess[..], out_ha1_hex);
    }
}

fn calculate_digest_ha2(
    algo: const u8[:],
    method: const u8[:],
    uri: const u8[:],
    is_auth_int: bool,
    body: const u8[:],
    out_ha2_hex: u8[..64]&,
) {
    var a2: u8[>..] = [];
    a2.append(method);
    a2.push(':');
    a2.append(uri);

    if is_auth_int {
        var h_body_hex: u8[..64] = [];
        digest_hash_hex(algo, body, h_body_hex);
        a2.push(':');
        a2.append(h_body_hex[..]);
    }

    digest_hash_hex(algo, a2[..], out_ha2_hex);
}

fn calculate_digest_response(
    algo: const u8[:],
    ha1_hex: const u8[:],
    nonce: const u8[:],
    nc_str: const u8[:],
    cnonce: const u8[:],
    has_qop: bool,
    is_auth_int: bool,
    ha2_hex: const u8[:],
    out_response_hex: u8[..64]&,
) {
    var a3: u8[>..] = [];
    a3.append(ha1_hex);
    a3.push(':');
    a3.append(nonce);

    if has_qop {
        let active_qop = if is_auth_int { "auth-int" } else { "auth" };
        a3.push(':');
        a3.append(nc_str);
        a3.push(':');
        a3.append(cnonce);
        a3.push(':');
        a3.append(active_qop);
    }

    a3.push(':');
    a3.append(ha2_hex);

    digest_hash_hex(algo, a3[..], out_response_hex);
}

fn serialize_digest_auth<B>(
    effective_user: const u8[:],
    realm: const u8[:],
    nonce: const u8[:],
    uri: const u8[:],
    algo: const u8[:],
    response_hex: const u8[:],
    active_qop: const u8[:],
    nc_str: const u8[:],
    cnonce: const u8[:],
    opaque: const u8[:],
    userhash: bool,
    out_header: B&,
) -> bool {
    let base_len = 17 + effective_user.len + 10 + realm.len + 10 + nonce.len + 8 + uri.len + 13 + algo.len + 13 + response_hex.len + 1;
    let qop_len = if active_qop.len > 0 { 6 + active_qop.len + 5 + nc_str.len + 10 + cnonce.len + 1 } else { 0 };
    let op_len = if opaque.len > 0 { 10 + opaque.len + 1 } else { 0 };
    let uh_len = if userhash { 16 } else { 0 };
    guard base_len + qop_len + op_len + uh_len <= out_header.cap else { return false; }

    out_header.clear();
    out_header.append("Digest username=\"");
    out_header.append(effective_user);
    out_header.append("\", realm=\"");
    out_header.append(realm);
    out_header.append("\", nonce=\"");
    out_header.append(nonce);
    out_header.append("\", uri=\"");
    out_header.append(uri);
    out_header.append("\", algorithm=");
    out_header.append(algo);
    out_header.append(", response=\"");
    out_header.append(response_hex);
    out_header.append("\"");

    if active_qop.len > 0 {
        out_header.append(", qop=");
        out_header.append(active_qop);
        out_header.append(", nc=");
        out_header.append(nc_str);
        out_header.append(", cnonce=\"");
        out_header.append(cnonce);
        out_header.append("\"");
    }

    if opaque.len > 0 {
        out_header.append(", opaque=\"");
        out_header.append(opaque);
        out_header.append("\"");
    }

    if userhash {
        out_header.append(", userhash=true");
    }

    return true;
}

// Computes RFC 7616 Digest response and outputs the full Authorization header
fn compute_digest_response(
    challenge: const DigestChallenge&,
    creds: const DigestCredentials&,
    method: const u8[:],
    uri: const u8[:],
    nc: u32,
    cnonce: const u8[:],
    body: const u8[:],
    out_header: u8[..512]&,
) -> bool {
    guard challenge.valid else { return false; }

    let algo = challenge.algorithm[..];
    let is_auth_int = eq_ascii_fold(challenge.qop[..], "auth-int");
    let has_qop = (challenge.qop.len > 0);

    var effective_user: u8[..128] = [];
    if challenge.userhash {
        var user_realm: u8[>..] = [];
        user_realm.append(creds.username[..]);
        user_realm.push(':');
        user_realm.append(challenge.realm[..]);
        digest_hash_hex(algo, user_realm[..], effective_user);
    } else {
        effective_user.append(creds.username[..]);
    }

    var ha1_hex: u8[..64] = [];
    calculate_digest_ha1(algo, effective_user[..], challenge.realm[..], creds.password[..], challenge.nonce[..], cnonce, ha1_hex);

    var ha2_hex: u8[..64] = [];
    calculate_digest_ha2(algo, method, uri, is_auth_int, body, ha2_hex);

    var nc_str: u8[..16] = [];
    core::format_u64_hex_fixed(nc, 8, nc_str, false);

    var response_hex: u8[..64] = [];
    calculate_digest_response(algo, ha1_hex[..], challenge.nonce[..], nc_str[..], cnonce, has_qop, is_auth_int, ha2_hex[..], response_hex);

    let active_qop: const u8[:] = if has_qop {
        if is_auth_int { "auth-int" } else { "auth" }
    } else {
        ""
    };

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
