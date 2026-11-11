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
    out.append_u16_be(challenge.token_type);
    out.append_u16_be(challenge.issuer_name.len as u16);
    out.append(challenge.issuer_name[..]);
    out.push(challenge.redemption_context.len as u8);
    out.append(challenge.redemption_context[..]);
    out.append_u16_be(challenge.origin_info.len as u16);
    out.append(challenge.origin_info[..]);
}

// Unmarshals TokenChallenge from RFC 9577 §2.1.1 binary wire representation.
fn unmarshal_token_challenge(data: const u8[:], out: TokenChallenge&) -> bool {
    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return false; }

    let iss, ok_iss = core::read_u16_prefixed(cur);
    guard ok_iss && iss.len > 0 else { return false; }

    let ctx, ok_ctx = core::read_u8_prefixed(cur);
    guard ok_ctx && (ctx.len == 0 || ctx.len == 32) else { return false; }

    let orig, ok_orig = core::read_u16_prefixed(cur);
    guard ok_orig && cur.buf.len == 0 else { return false; }

    guard out.issuer_name.try_set(iss) &&
        out.redemption_context.try_set(ctx) &&
        out.origin_info.try_set(orig) else {
        out = TokenChallenge { .. };
        return false;
    }
    out.token_type = token_type;
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
    out.append_u16_be(token.token_type);
    out.append(token.nonce[..]);
    out.append(token.challenge_digest[..]);
    out.append(token.token_key_id[..]);
    out.append(token.authenticator[..]);
}

// Unmarshals Token from RFC 9577 §2.2.1 binary representation.
fn unmarshal_token(data: const u8[:], key_id_len: i64, auth_len: i64, out: Token&) -> bool {
    guard key_id_len >= 0 && auth_len >= 0 else { return false; }

    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return false; }

    let nonce_slice, ok_n = core::read_bytes(cur, 32);
    let digest_slice, ok_d = core::read_bytes(cur, 32);
    let key_id_slice, ok_k = core::read_bytes(cur, key_id_len);
    let auth_slice, ok_a = core::read_bytes(cur, auth_len);
    guard ok_n && ok_d && ok_k && ok_a && cur.buf.len == 0 else { return false; }
    guard out.token_key_id.try_set(key_id_slice) && out.authenticator.try_set(auth_slice) else {
        out = Token { .. };
        return false;
    }

    out.token_type = token_type;
    for i in 32 {
        out.nonce[i] = nonce_slice[i];
        out.challenge_digest[i] = digest_slice[i];
    }
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
    guard idx >= 0 && idx <= rem.len else { return "", false; }
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };

    let after_key = rem[idx..].trim_lws_start();
    guard after_key.len > 0 && after_key[0] == '=' else { return "", false; }
    let after_eq = after_key[1..].trim_lws_start();
    guard after_eq.len > 0 else { return "", false; }

    let v_start = core::sub_sat_i64(rem.len, after_eq.len);
    if after_eq[0] == '"' {
        let quoted_body = after_eq[1..];
        let rel_q = quoted_body.index_of_byte('"');
        guard rel_q >= 0 else { return "", false; }
        let val = quoted_body[..rel_q];
        guard !val.contains_byte('\\') && core::swar_find_ctl(val) == val.len else { return "", false; }
        let next_idx = core::add_sat_i64(v_start, core::add_sat_i64(rel_q, 2));
        guard next_idx <= rem.len else { return "", false; }
        let tail = rem[next_idx..];
        guard tail.len == 0 || core::is_lws(tail[0]) || tail[0] == ',' else { return "", false; }
        idx = next_idx;
        committed = true;
        return val, true;
    }
    let delim = core::find_byteset(after_eq, ", \t");
    let v_len = if delim >= 0 { delim } else { after_eq.len };
    let val = after_eq[..v_len];
    guard is_valid_cors_token(val) else { return "", false; }
    idx = core::add_sat_i64(v_start, v_len);
    committed = true;
    return val, true;
}

// Decodes base64url-encoded token-key parameter into buffer.
//
// Example:
//   val = "ZXhhbXBsZQ"
//   returns: ok = true, temp_token_key = "example"
fn decode_token_key_param(val: const u8[:], temp_token_key: u8[..512]&) -> bool {
    guard val.len > 0 else { return false; }
    var raw_key: u8[..512] = [];
    guard core::base64url_decode(val, raw_key) && raw_key.len > 0 else { return false; }
    return temp_token_key.try_set(raw_key[..]);
}

// Scans an auth-param key token up to `=`, `,`, or whitespace.
//
// Example:
//   rem = "challenge=\"xyz\""
//   returns: "challenge"
fn read_param_key(rem: const u8[:]) -> const u8[:] {
    let delim = core::find_byteset(rem, "=, \t");
    return if delim >= 0 { rem[..delim] } else { rem };
}

// Advances `idx` past optional LWS and a required comma separator between auth-params (RFC 9110 Section 11.2).
//
// Example:
//   params_str = ", max-age=60", idx = 0
//   returns: true, idx = 1
inline fn consume_challenge_param_delimiter(params_str: const u8[:], idx: i64&) -> bool {
    let after_val = params_str[idx..].trim_lws_start();
    idx = core::sub_sat_i64(params_str.len, after_val.len);
    guard idx < params_str.len else { return true; }
    guard params_str[idx] == ',' else { return false; }
    idx = core::add_sat_i64(idx, 1);
    return params_str[idx..].trim_lws().len > 0;
}

// Parses comma-separated PrivateToken challenge parameters.
//
// Example:
//   params_str = "challenge=\"xyz\", max-age=3600"
//   returns: "xyz", ok = true
fn parse_challenge_params(
    params_str:     const u8[:],
    temp_token_key: u8[..512]&,
    temp_max_age:   i64&,
) -> const u8[:], bool {
    var challenge_slice = params_str[..0];
    var seen_challenge = false;
    var seen_token_key = false;
    var seen_max_age = false;
    var idx: i64 = 0;
    while idx < params_str.len {
        let rem = params_str[idx..].trim_lws_start();
        idx = core::sub_sat_i64(params_str.len, rem.len);
        guard idx < params_str.len else { break; }

        let key = read_param_key(rem);
        guard is_valid_cors_token(key) else { return "", false; }
        idx = core::add_sat_i64(idx, key.len);

        let val, ok_v = parse_param_val(params_str, idx);
        guard ok_v else { return "", false; }

        if key.eq_ascii_fold("challenge") {
            guard !seen_challenge && val.len > 0 else { return "", false; }
            seen_challenge = true;
            challenge_slice = val;
        } else if key.eq_ascii_fold("token-key") {
            guard !seen_token_key && decode_token_key_param(val, temp_token_key) else { return "", false; }
            seen_token_key = true;
        } else if key.eq_ascii_fold("max-age") {
            guard !seen_max_age else { return "", false; }
            let secs, ok_sec = val.parse_i64_dec();
            guard ok_sec && secs >= 0 else { return "", false; }
            seen_max_age = true;
            temp_max_age = secs;
        }
        guard consume_challenge_param_delimiter(params_str, idx) else { return "", false; }
    }
    return challenge_slice, challenge_slice.len > 0;
}

// Parses `WWW-Authenticate: PrivateToken challenge="<base64url>", ...` header.
//
// Example:
//   header_val = "PrivateToken challenge=\"AQIDBA\", token-key=\"xyz\""
//   returns: ok = true
fn parse_private_token_challenge<B>(
    header_val:      const u8[:],
    out_challenge:   TokenChallenge&,
    out_token_key:   B&,
    out_max_age_sec: i64&,
) -> bool {
    let clean = header_val.trim_lws();
    let scheme_len = rfc::SCHEME_PRIVATE_TOKEN.len;
    guard clean.len > scheme_len else { return false; }
    guard clean[..scheme_len].eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) else { return false; }
    let sep = clean[scheme_len];
    guard core::is_lws(sep) else { return false; }

    var temp_token_key: u8[..512] = [];
    var temp_max_age:   i64       = 0;
    let params_start = core::add_sat_i64(scheme_len, 1);
    let challenge_slice, ok_params = parse_challenge_params(
        clean[params_start..].trim_lws(),
        temp_token_key,
        temp_max_age,
    );
    guard ok_params else { return false; }

    var raw_challenge: u8[..512] = [];
    guard core::base64url_decode(challenge_slice, raw_challenge) else { return false; }

    var temp_chal = TokenChallenge { .. };
    guard unmarshal_token_challenge(raw_challenge[..], temp_chal) else { return false; }

    guard can_fit(out_token_key, temp_token_key.len) else { return false; }
    out_token_key.clear();
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
    var earliest_idx: i64 = 0;
    var earliest_exp: i64 = 9223372036854775807;
    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if entry.used || (entry.expires_at_sec > 0 && now_sec > entry.expires_at_sec) {
            return i;
        }
        if entry.expires_at_sec > 0 && entry.expires_at_sec < earliest_exp {
            earliest_exp = entry.expires_at_sec;
            earliest_idx = i;
        }
    }
    if cache.entries.len < cache.entries.cap {
        return -1;
    }
    return earliest_idx;
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
    guard raw_token.len > 0 && raw_token.len <= 512 && ttl_sec >= 0 && now_sec >= 0 else { return false; }
    let digest = compute_challenge_digest(challenge);
    var target_idx = find_free_token_slot(cache, now_sec);

    if target_idx == -1 {
        target_idx = cache.entries.len;
        guard cache.entries.try_push(CachedToken { .. }) else { return false; }
    }

    let entry = &cache.entries[target_idx];
    guard entry.raw_token.try_set(raw_token) else { return false; }
    entry.challenge_digest = digest;
    entry.token = token;
    entry.expires_at_sec = if ttl_sec > 0 { core::add_sat_i64(now_sec, ttl_sec) } else { 0 };
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
            guard out_raw.try_set(entry.raw_token[..]) else { return false; }
            out_token = entry.token;
            cache.entries[i].used = true;
            return true;
        }
    }

    out_token = Token { .. };
    out_raw.clear();
    return false;
}

// Pops and consumes a single-use token matching the challenge digest (RFC 9577 §2.1.4 single-spend).
fn pop_private_token<B>(
    cache:            PrivateTokenCache&,
    challenge_digest: const u8[32]&,
    now_sec:          i64,
    out_raw_token:    B&,
) -> bool {
    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if entry_matches_challenge(entry, challenge_digest, now_sec) {
            guard out_raw_token.try_set(entry.raw_token[..]) else { return false; }
            cache.entries[i].used = true;
            return true;
        }
    }
    out_raw_token.clear();
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
        guard entry_name(res.headers, e).eq_ascii_fold("WWW-Authenticate") else { continue; }
        let val = entry_value(res.headers, e).trim_lws();
        guard val.len >= scheme_len && val[..scheme_len].eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) else { continue; }
        if val.len == scheme_len || core::is_lws(val[scheme_len]) {
            return true;
        }
    }
    return false;
}
