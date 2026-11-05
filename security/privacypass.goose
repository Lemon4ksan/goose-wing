// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9576 Privacy Pass Architecture, RFC 9577 PrivateToken HTTP Authentication,
// and RFC 9578 Blind RSA Token Issuance for anti-bot WAF bypass and privacy authorization.
// Zero-heap binary wire serialization, challenge parsing, redemption caching, and header codecs.
namespace wing;

import std;
import core from "..";
import rfc.http;

// ---- Data Structures -----------------------------------------------------

struct TokenChallenge {
    token_type:         u16       = rfc::TOKEN_TYPE_BLIND_RSA,
    issuer_name:        u8[..128] = [],
    redemption_context: u8[..32]  = [],
    origin_info:        u8[..256] = [],
}

struct Token {
    token_type:       u16       = rfc::TOKEN_TYPE_BLIND_RSA,
    nonce:            u8[32]    = [0; 32],
    challenge_digest: u8[32]    = [0; 32],
    token_key_id:     u8[..32]  = [],
    authenticator:    u8[..256] = [],
}

struct CachedToken {
    challenge_digest: u8[32]    = [0; 32],
    token:            Token     = Token { .. },
    raw_token:        u8[..512] = [],
    expires_at_sec:   i64       = 0,
    used:             bool      = false,
}

struct PrivateTokenCache {
    entries: CachedToken[..16] = [],
}

// ---- Wire Binary Marshaling & Unmarshaling (RFC 9577 §2.1.1 & §2.2.1) ----

// Marshals TokenChallenge into RFC 9577 §2.1.1 wire presentation format:
// token_type(2) + issuer_len(2) + issuer + ctx_len(1) + ctx + origin_len(2) + origin
fn marshal_token_challenge<B>(challenge: const TokenChallenge&, out: B&) {
    out.clear();
    core::write_be_u16(out, challenge.token_type);
    core::write_be_u16(out, challenge.issuer_name.len as u16);
    out.append(challenge.issuer_name[..]);
    out.push(challenge.redemption_context.len as u8);
    out.append(challenge.redemption_context[..]);
    core::write_be_u16(out, challenge.origin_info.len as u16);
    out.append(challenge.origin_info[..]);
}

// Unmarshals TokenChallenge from RFC 9577 §2.1.1 binary wire representation.
fn unmarshal_token_challenge(data: const u8[:], out: TokenChallenge&) -> bool {
    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return false; }

    let iss, ok_iss = core::read_u16_prefixed(cur);
    guard ok_iss && iss.len > 0 && iss.len <= out.issuer_name.cap else { return false; }

    let ctx, ok_ctx = core::read_u8_prefixed(cur);
    guard ok_ctx && (ctx.len == 0 || ctx.len == 32) && ctx.len <= out.redemption_context.cap else {
        return false;
    }

    let orig, ok_orig = core::read_u16_prefixed(cur);
    guard ok_orig && orig.len <= out.origin_info.cap && cur.buf.len == 0 else { return false; }

    out.token_type = token_type;
    out.issuer_name.clear();
    out.issuer_name.append(iss);
    out.redemption_context.clear();
    out.redemption_context.append(ctx);
    out.origin_info.clear();
    out.origin_info.append(orig);
    return true;
}

// Computes SHA-256(TokenChallenge) as defined in RFC 9577 §2.2.1.
fn compute_challenge_digest(challenge: const TokenChallenge&) -> u8[32] {
    var raw: u8[..512] = [];
    marshal_token_challenge(challenge, raw);
    return core::sha256(raw[..]);
}

// Marshals Token into RFC 9577 §2.2.1 wire format:
// token_type(2) + nonce(32) + challenge_digest(32) + key_id(Nid) + authenticator(Nk)
fn marshal_token<B>(token: const Token&, out: B&) {
    out.clear();
    core::write_be_u16(out, token.token_type);
    out.append(token.nonce[..]);
    out.append(token.challenge_digest[..]);
    out.append(token.token_key_id[..]);
    out.append(token.authenticator[..]);
}

// Unmarshals Token from RFC 9577 §2.2.1 binary representation.
fn unmarshal_token(data: const u8[:], key_id_len: i64, auth_len: i64, out: Token&) -> bool {
    guard key_id_len >= 0 && auth_len >= 0 else { return false; }
    guard key_id_len <= out.token_key_id.cap && auth_len <= out.authenticator.cap else { return false; }

    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return false; }

    let nonce_slice, ok_n = core::read_bytes(cur, 32);
    let digest_slice, ok_d = core::read_bytes(cur, 32);
    let key_id_slice, ok_k = core::read_bytes(cur, key_id_len);
    let auth_slice, ok_a = core::read_bytes(cur, auth_len);
    guard ok_n && ok_d && ok_k && ok_a && cur.buf.len == 0 else { return false; }

    out.token_type = token_type;
    for i in 32 {
        out.nonce[i] = nonce_slice[i];
        out.challenge_digest[i] = digest_slice[i];
    }
    out.token_key_id.clear();
    out.token_key_id.append(key_id_slice);
    out.authenticator.clear();
    out.authenticator.append(auth_slice);
    return true;
}

// ---- HTTP Authentication Header Parsing & Formatting (RFC 9577 §2.1 & §2.2)

// Extracts parameter value from key-value parameter string.
// Leaves `idx` unchanged on error.
//
// Example:
//   rem = "= \"abc\", def", idx = 0
//   returns: "abc", ok = true, idx = 7
fn parse_param_val(rem: const u8[:], idx: i64&) -> const u8[:], bool {
    var cur = idx;
    while cur < rem.len && (rem[cur] == ' ' || rem[cur] == '\t') {
        cur += 1;
    }
    guard cur < rem.len && rem[cur] == '=' else { return "", false; }
    cur += 1;
    while cur < rem.len && (rem[cur] == ' ' || rem[cur] == '\t') {
        cur += 1;
    }
    guard cur < rem.len else { return "", false; }
    if rem[cur] == '"' {
        cur += 1;
        let v_start = cur;
        let rel_q = core::index_of_byte(rem[v_start..], '"');
        guard rel_q >= 0 else { return "", false; }
        let val = rem[v_start..v_start + rel_q];
        idx = v_start + rel_q + 1;
        return val, true;
    }
    let v_start = cur;
    while cur < rem.len && rem[cur] != ',' && rem[cur] != ' ' && rem[cur] != '\t' {
        cur += 1;
    }
    guard cur > v_start else { return "", false; }
    idx = cur;
    return rem[v_start..cur], true;
}

// Decodes base64url-encoded token-key parameter into buffer.
//
// Example:
//   val = "ZXhhbXBsZQ"
//   returns: ok = true, temp_token_key = "example"
fn decode_token_key_param(val: const u8[:], temp_token_key: u8[..128]&) -> bool {
    var raw_key: u8[..128] = [];
    guard core::base64url_decode(val, raw_key) else { return false; }
    return temp_token_key.try_set(raw_key[..]);
}

// Applies a single parsed PrivateToken auth-param (`challenge`, `token-key`, `max-age`).
//
// Example:
//   key = "challenge", val = "AQIDBA", temp_token_key = [], temp_max_age = 0
//   returns: "AQIDBA", ok = true
fn apply_challenge_param(
    key:            const u8[:],
    val:            const u8[:],
    temp_token_key: u8[..128]&,
    temp_max_age:   i64&,
) -> const u8[:], bool {
    if eq_ascii_fold(key, "challenge") {
        guard val.len > 0 else { return "", false; }
        return val, true;
    }
    if eq_ascii_fold(key, "token-key") {
        guard decode_token_key_param(val, temp_token_key) else { return "", false; }
        return "", true;
    }
    if eq_ascii_fold(key, "max-age") {
        let secs, ok_sec = val.parse_i64_dec();
        guard ok_sec && secs >= 0 else { return "", false; }
        temp_max_age = secs;
        return "", true;
    }
    return "", true;
}

// Scans an auth-param key token up to `=`, `,`, or whitespace.
//
// Example:
//   rem = "challenge=\"xyz\""
//   returns: "challenge"
fn read_param_key(rem: const u8[:]) -> const u8[:] {
    var k_len: i64 = 0;
    while k_len < rem.len && rem[k_len] != '=' && rem[k_len] != ',' && rem[k_len] != ' ' && rem[k_len] != '\t' {
        k_len += 1;
    }
    return rem[..k_len];
}

// Parses comma-separated PrivateToken challenge parameters.
//
// Example:
//   params_str = "challenge=\"xyz\", max-age=3600"
//   returns: "xyz", ok = true
fn parse_challenge_params(
    params_str:     const u8[:],
    temp_token_key: u8[..128]&,
    temp_max_age:   i64&,
) -> const u8[:], bool {
    var challenge_slice = params_str[..0];
    var idx: i64 = 0;
    while idx < params_str.len {
        let rem = params_str[idx..].trim_start_bytes(" \t,");
        idx = params_str.len - rem.len;
        guard idx < params_str.len else { break; }

        let key = read_param_key(rem);
        guard key.len > 0 else { return "", false; }
        idx += key.len;

        let val, ok_v = parse_param_val(params_str, idx);
        guard ok_v else { return "", false; }

        let chal, ok_param = apply_challenge_param(key, val, temp_token_key, temp_max_age);
        guard ok_param else { return "", false; }
        if chal.len > 0 {
            challenge_slice = chal;
        }
    }
    return challenge_slice, challenge_slice.len > 0;
}

// Parses `WWW-Authenticate: PrivateToken challenge="<base64url>", ...` header.
//
// Example:
//   header_val = "PrivateToken challenge=\"AQIDBA\", token-key=\"xyz\""
//   returns: ok = true
fn parse_private_token_challenge(
    header_val:      const u8[:],
    out_challenge:   TokenChallenge&,
    out_token_key:   u8[..128]&,
    out_max_age_sec: i64&,
) -> bool {
    out_challenge = TokenChallenge { .. };
    out_token_key.clear();
    out_max_age_sec = 0;

    let clean = trim_lws(header_val);
    let scheme_len = rfc::SCHEME_PRIVATE_TOKEN.len;
    guard clean.len > scheme_len else { return false; }
    guard eq_ascii_fold(clean[..scheme_len], rfc::SCHEME_PRIVATE_TOKEN) else { return false; }
    let sep = clean[scheme_len];
    guard sep == ' ' || sep == '\t' else { return false; }

    var temp_token_key: u8[..128] = [];
    var temp_max_age:   i64       = 0;
    let challenge_slice, ok_params = parse_challenge_params(
        clean[scheme_len + 1..].trim_lws(),
        temp_token_key,
        temp_max_age,
    );
    guard ok_params else { return false; }

    var raw_challenge: u8[..512] = [];
    guard core::base64url_decode(challenge_slice, raw_challenge) else { return false; }

    var temp_chal = TokenChallenge { .. };
    guard unmarshal_token_challenge(raw_challenge[..], temp_chal) else { return false; }

    out_token_key.append(temp_token_key[..]);
    out_max_age_sec = temp_max_age;
    out_challenge = temp_chal;
    return true;
}

// Formats `Authorization: PrivateToken token="..."` header (RFC 9577 §2.2.2).
fn format_private_token_authorization<B>(token_bytes: const u8[:], out: B&) {
    out.clear();
    out.append("PrivateToken token=\"");
    core::base64url_encode(token_bytes, out);
    out.push('"' as u8);
}

// Formats W3C `Sec-Private-State-Token` header.
fn format_sec_private_state_token<B>(token_bytes: const u8[:], out: B&) {
    out.clear();
    core::base64url_encode(token_bytes, out);
}

// ---- Private Token Cache & Redemption Management -------------------------

fn find_free_token_slot(cache: const PrivateTokenCache&, now_sec: i64) -> i64 {
    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if entry.used || (entry.expires_at_sec > 0 && now_sec > entry.expires_at_sec) {
            return i;
        }
    }
    return -1;
}

// Puts a pre-issued or blinded token into cache for a challenge.
fn put_private_token(
    cache:     PrivateTokenCache&,
    challenge: const TokenChallenge&,
    token:     const Token&,
    raw_token: const u8[:],
    ttl_sec:   i64,
    now_sec:   i64,
) -> bool {
    guard raw_token.len <= 512 else { return false; }
    let digest = compute_challenge_digest(challenge);
    var target_idx = find_free_token_slot(cache, now_sec);

    if target_idx == -1 {
        if cache.entries.len < cache.entries.cap {
            target_idx = cache.entries.len;
            cache.entries.push(CachedToken { .. });
        } else {
            target_idx = 0;
        }
    }

    let entry = &cache.entries[target_idx];
    entry.challenge_digest = digest;
    entry.token = token;
    entry.raw_token.clear();
    entry.raw_token.append(raw_token);
    if ttl_sec > 0 && now_sec >= 0 {
        let sum_u = core::add_sat_u64(now_sec as u64, ttl_sec as u64);
        entry.expires_at_sec = min(sum_u, 9223372036854775807) as! i64;
    } else {
        entry.expires_at_sec = 0;
    }
    entry.used = false;

    return true;
}

fn entry_matches_challenge(entry: const CachedToken&, digest: const u8[32]&, now_sec: i64) -> bool {
    guard !entry.used else { return false; }
    guard entry.expires_at_sec == 0 || now_sec <= entry.expires_at_sec else { return false; }
    // RFC 9577 Section 2.1.4: Token Caching - Cached tokens can only be redeemed when they match all of the fields in the TokenChallenge.
    return core::ct_eq_bytes(entry.challenge_digest[..], digest[..]);
}

// Gets and consumes a single-use token matching the challenge (RFC 9577 §2.1.4 single-spend).
fn get_private_token(
    cache:     PrivateTokenCache&,
    challenge: const TokenChallenge&,
    now_sec:   i64,
    out_token: Token&,
    out_raw:   u8[..512]&,
) -> bool {
    let digest = compute_challenge_digest(challenge);

    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if entry_matches_challenge(entry, digest, now_sec) {
            out_token = entry.token;
            out_raw.clear();
            out_raw.append(entry.raw_token[..]);
            cache.entries[i].used = true;
            return true;
        }
    }

    out_token = Token { .. };
    out_raw.clear();
    return false;
}

// Attaches an Authorization: PrivateToken header to an outbound request.
fn attach_private_token<R>(req: R&, token_bytes: const u8[:]) {
    var auth_header: u8[..1024] = [];
    format_private_token_authorization(token_bytes, auth_header);
    set_header(req, "Authorization", auth_header[..]);
}

// Checks whether an HTTP response has a PrivateToken challenge.
fn has_private_token_challenge<Res>(res: const Res&) -> bool {
    guard res.status_code == rfc::STATUS_UNAUTHORIZED else { return false; }
    let scheme_len = rfc::SCHEME_PRIVATE_TOKEN.len;
    for &e in res.headers.entries {
        guard core::eq_ascii_fold(entry_name(res.headers, e), "WWW-Authenticate") else { continue; }
        let val = trim_lws(entry_value(res.headers, e));
        guard val.len >= scheme_len && eq_ascii_fold(val[..scheme_len], rfc::SCHEME_PRIVATE_TOKEN) else { continue; }
        if val.len == scheme_len || val[scheme_len] == ' ' || val[scheme_len] == '\t' {
            return true;
        }
    }
    return false;
}
