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

// RFC 9577 Section 2.1.1.1: Server Name Encoding - Authority host[:port] without userinfo, path, or whitespace.
inline fn is_valid_privacypass_server_name(s: const u8[:]) -> bool {
    guard s.len > 0 && core::find_byteset(s, "@/?#\\ \t,") < 0 && core::swar_find_ctl(s) == s.len else {
        return false;
    }
    var probe: u8[..272] = "https://";
    guard probe.try_append(s) else { return false; }
    return extract_hostname_from_origin(probe[..]).len > 0;
}

inline fn is_valid_privacypass_origin_info(orig: const u8[:]) -> bool {
    if orig.len == 0 { return true; }
    var tok = core::make_byte_tokenizer(orig, ',');
    loop {
        let item, ok = core::token_next(tok);
        guard ok else { break; }
        guard is_valid_privacypass_server_name(item) else { return false; }
    }
    return true;
}

// Unmarshals TokenChallenge from RFC 9577 §2.1.1 binary wire representation.
fn unmarshal_token_challenge(data: const u8[:], out: TokenChallenge&) -> bool {
    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return false; }

    let iss, ok_iss = core::read_u16_prefixed(cur);
    guard ok_iss && is_valid_privacypass_server_name(iss) else { return false; }

    let ctx, ok_ctx = core::read_u8_prefixed(cur);
    guard ok_ctx && (ctx.len == 0 || ctx.len == 32) else { return false; }

    let orig, ok_orig = core::read_u16_prefixed(cur);
    guard ok_orig && cur.buf.len == 0 && is_valid_privacypass_origin_info(orig) else { return false; }

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
    guard key_id_len > 0 && key_id_len <= 32 && auth_len > 0 && auth_len <= 256 else { return false; }

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

inline fn is_valid_quoted_pair_byte(b: u8) -> bool {
    return b == '\t' || b == ' ' || (b >= 0x21 && b <= 0x7E) || b >= 0x80;
}

inline fn is_valid_qdtext_byte(b: u8) -> bool {
    return b == '\t' || b == ' ' || b == 0x21 || (b >= 0x23 && b <= 0x5B) ||
        (b >= 0x5D && b <= 0x7E) || b >= 0x80;
}

// Scans an RFC 9110 Section 5.6.4 quoted-string starting at `quoted[0] == '"'`.
// Writes unescaped payload into `out_val` and returns consumed byte count including both quotes.
//
// Example:
//   quoted = "\"a\\\"b\", next"
//   returns: consumed = 6, ok = true, out_val = "a\"b"
inline fn decode_auth_quoted_string(quoted: const u8[:], out_val: u8[..512]&) -> i64, bool {
    out_val.clear();
    guard quoted.len >= 2 && quoted[0] == '"' else { return 0, false; }
    var pos: i64 = 1;
    while pos < quoted.len {
        let b = quoted[pos];
        if b == '"' {
            return core::add_sat_i64(pos, 1), true;
        }
        if b == '\\' {
            pos = core::add_sat_i64(pos, 1);
            guard pos < quoted.len && is_valid_quoted_pair_byte(quoted[pos]) else {
                out_val.clear();
                return 0, false;
            }
            guard out_val.try_push(quoted[pos]) else {
                out_val.clear();
                return 0, false;
            }
        } else {
            guard is_valid_qdtext_byte(b) && out_val.try_push(b) else {
                out_val.clear();
                return 0, false;
            }
        }
        pos = core::add_sat_i64(pos, 1);
    }
    out_val.clear();
    return 0, false;
}

// Extracts parameter value from key-value parameter string into `out_val`.
// Leaves `idx` unchanged and clears `out_val` on error.
//
// Example:
//   rem = "= \"abc\", def", idx = 0
//   returns: true, idx = 7, out_val = "abc"
fn parse_param_val(rem: const u8[:], idx: i64&, out_val: u8[..512]&) -> bool {
    out_val.clear();
    guard idx >= 0 && idx <= rem.len else { return false; }
    let saved_idx = idx;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        out_val.clear();
    };

    let after_key = rem[idx..].trim_lws_start();
    guard after_key.len > 0 && after_key[0] == '=' else { return false; }
    let after_eq = after_key[1..].trim_lws_start();
    guard after_eq.len > 0 else { return false; }

    let v_start = core::sub_sat_i64(rem.len, after_eq.len);
    if after_eq[0] == '"' {
        let consumed_q, ok_q = decode_auth_quoted_string(after_eq, out_val);
        guard ok_q else { return false; }
        let next_idx = core::add_sat_i64(v_start, consumed_q);
        guard next_idx <= rem.len else { return false; }
        let tail = rem[next_idx..];
        guard tail.len == 0 || core::is_lws(tail[0]) || tail[0] == ',' else { return false; }
        idx = next_idx;
        committed = true;
        return true;
    }
    let delim = core::find_byteset(after_eq, ", \t");
    let v_len = if delim >= 0 { delim } else { after_eq.len };
    let val = after_eq[..v_len];
    guard is_valid_cors_token(val) && out_val.try_set(val) else { return false; }
    idx = core::add_sat_i64(v_start, v_len);
    committed = true;
    return true;
}

// Validates and stores a padded base64url-encoded challenge parameter (RFC 9577 Section 2.1.2).
//
// Example:
//   val = "AQIDBA=="
//   returns: true, challenge_b64 = "AQIDBA=="
fn decode_challenge_b64_param(val: const u8[:], challenge_b64: u8[..512]&) -> bool {
    // RFC 9577 Section 2.1.2: Sending Token Challenges - The challenge base64url value MUST include padding.
    guard val.len > 0 && core::is_valid_padded_base64url(val) else { return false; }
    return challenge_b64.try_set(val);
}

// Decodes padded base64url-encoded token-key parameter into buffer (RFC 9577 Section 2.1.2).
//
// Example:
//   val = "ZXhhbXBsZQ=="
//   returns: ok = true, temp_token_key = "example"
fn decode_token_key_param(val: const u8[:], temp_token_key: u8[..512]&) -> bool {
    // RFC 9577 Section 2.1.2: Sending Token Challenges - The token-key base64url value MUST include padding.
    guard val.len > 0 && core::is_valid_padded_base64url(val) else { return false; }
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

// Checks whether `rem` (at the start of a comma-delimited item) begins a new auth-scheme challenge
// rather than an `auth-param` (`token BWS "=" ...`) of the current challenge (RFC 9110 Section 11.2).
inline fn is_next_auth_challenge_start(rem: const u8[:]) -> bool {
    let tok = read_param_key(rem);
    guard is_valid_cors_token(tok) else { return false; }
    let rest = rem[tok.len..];
    if rest.len == 0 || rest[0] == ',' {
        return true;
    }
    guard core::is_lws(rest[0]) else { return false; }
    let after_ws = rest.trim_lws_start();
    return after_ws.len == 0 || after_ws[0] != '=';
}

// Advances `idx` past optional LWS and a required comma separator between auth-params or challenges.
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

inline fn apply_privacypass_param(
    key:            const u8[:],
    val:            const u8[:],
    seen_mask:      u8&,
    challenge_b64:  u8[..512]&,
    temp_token_key: u8[..512]&,
    temp_max_age:   i64&,
) -> bool {
    if key.eq_ascii_fold("challenge") {
        guard (seen_mask & 1) == 0 && decode_challenge_b64_param(val, challenge_b64) else { return false; }
        seen_mask |= 1;
        return true;
    }
    if key.eq_ascii_fold("token-key") {
        guard (seen_mask & 2) == 0 && decode_token_key_param(val, temp_token_key) else { return false; }
        seen_mask |= 2;
        return true;
    }
    if key.eq_ascii_fold("max-age") {
        guard (seen_mask & 4) == 0 else { return false; }
        let secs, ok_sec = val.parse_i64_dec();
        guard ok_sec && secs >= 0 else { return false; }
        seen_mask |= 4;
        temp_max_age = secs;
        return true;
    }
    return true;
}

// Parses comma-separated PrivateToken challenge parameters starting at `idx`, stopping if a subsequent
// challenge scheme begins after a comma (RFC 9577 Section 2.1.2.1).
//
// Example:
//   raw = "challenge=\"AQIDBA==\", max-age=3600", idx = 0
//   returns: true, idx = 34, challenge_b64 = "AQIDBA=="
fn parse_challenge_params(
    raw:            const u8[:],
    idx:            i64&,
    challenge_b64:  u8[..512]&,
    temp_token_key: u8[..512]&,
    temp_max_age:   i64&,
) -> bool {
    let saved_idx = idx;
    challenge_b64.clear();
    temp_token_key.clear();
    temp_max_age = 0;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        challenge_b64.clear();
        temp_token_key.clear();
        temp_max_age = 0;
    };

    var seen_mask: u8 = 0;
    var first_param = true;
    while idx < raw.len {
        let rem = raw[idx..].trim_lws_start();
        idx = core::sub_sat_i64(raw.len, rem.len);
        guard idx < raw.len else { break; }
        if !first_param && is_next_auth_challenge_start(rem) {
            break;
        }
        first_param = false;

        let key = read_param_key(rem);
        guard is_valid_cors_token(key) else { return false; }
        idx = core::add_sat_i64(idx, key.len);

        var val_buf: u8[..512] = [];
        guard parse_param_val(raw, idx, val_buf) else { return false; }
        guard apply_privacypass_param(
            key, val_buf[..], seen_mask, challenge_b64, temp_token_key, temp_max_age,
        ) else {
            return false;
        }
        guard consume_challenge_param_delimiter(raw, idx) else { return false; }
    }
    guard challenge_b64.len > 0 else { return false; }
    committed = true;
    return true;
}

inline fn is_valid_token68_slice(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    var seen_eq = false;
    for b in s {
        if b == '=' {
            seen_eq = true;
            continue;
        }
        guard !seen_eq else { return false; }
        let ok = core::is_ascii_alphanumeric(b) || b == '-' || b == '.' || b == '_' ||
            b == '~' || b == '+' || b == '/';
        guard ok else { return false; }
    }
    return true;
}

inline fn try_skip_token68_challenge_param(raw: const u8[:], rem_init: const u8[:], idx: i64&) -> bool, bool {
    let first_tok = read_param_key(rem_init);
    let after_first = rem_init[first_tok.len..].trim_lws_start();
    let tok68_cand = rem_init[..core::sub_sat_i64(rem_init.len, after_first.len)].trim_lws_end();
    let is_tok68 = after_first.len == 0 || (after_first[0] == ',' && is_valid_token68_slice(tok68_cand));
    guard is_tok68 else { return false, true; }
    let tok68_end = core::find_byteset(rem_init, ", \t");
    let tlen = if tok68_end >= 0 { tok68_end } else { rem_init.len };
    guard is_valid_token68_slice(rem_init[..tlen]) else { return true, false; }
    idx = core::add_sat_i64(idx, tlen);
    return true, consume_challenge_param_delimiter(raw, idx);
}

// Skips non-PrivateToken challenge parameters (or token68) up to the next challenge in `WWW-Authenticate`.
//
// Example:
//   raw = "realm=\"grease\", PrivateToken challenge=\"AQID\"", idx = 0
//   returns: true, idx = 16
fn skip_other_auth_challenge_params(raw: const u8[:], idx: i64&) -> bool {
    let rem_init = raw[idx..].trim_lws_start();
    idx = core::sub_sat_i64(raw.len, rem_init.len);
    guard idx < raw.len else { return true; }

    let handled_tok68, ok_tok68 = try_skip_token68_challenge_param(raw, rem_init, idx);
    if handled_tok68 {
        return ok_tok68;
    }

    var first_param = true;
    while idx < raw.len {
        let rem = raw[idx..].trim_lws_start();
        idx = core::sub_sat_i64(raw.len, rem.len);
        guard idx < raw.len else { break; }
        if !first_param && is_next_auth_challenge_start(rem) {
            break;
        }
        first_param = false;
        let key = read_param_key(rem);
        guard is_valid_cors_token(key) else { return false; }
        idx = core::add_sat_i64(idx, key.len);
        var val_buf: u8[..512] = [];
        guard parse_param_val(raw, idx, val_buf) else { return false; }
        guard consume_challenge_param_delimiter(raw, idx) else { return false; }
    }
    return true;
}

// Parses `WWW-Authenticate: PrivateToken challenge="<base64url>", ...` header (including multi-challenge lists).
//
// Example:
//   header_val = "PrivateToken challenge=\"AAIADmlzc3Vlci5leGFtcGxlAAAA\", token-key=\"ZXhhbXBsZQ==\""
//   returns: ok = true
fn parse_private_token_challenge<B>(
    header_val:      const u8[:],
    out_challenge:   TokenChallenge&,
    out_token_key:   B&,
    out_max_age_sec: i64&,
) -> bool {
    let clean = header_val.trim_lws();
    guard clean.len > 0 else { return false; }

    var matched = false;
    var best_chal = TokenChallenge { .. };
    var best_key: u8[..512] = [];
    var best_age: i64       = 0;

    var idx: i64 = 0;
    while idx < clean.len {
        let rem = clean[idx..].trim_lws_start();
        idx = core::sub_sat_i64(clean.len, rem.len);
        guard idx < clean.len else { break; }

        let scheme = read_param_key(rem);
        guard is_valid_cors_token(scheme) else { return false; }
        idx = core::add_sat_i64(idx, scheme.len);

        if scheme.eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) {
            guard idx < clean.len && core::is_lws(clean[idx]) else { return false; }
            idx = core::add_sat_i64(idx, 1);
            var challenge_b64:  u8[..512] = [];
            var temp_token_key: u8[..512] = [];
            var temp_max_age:   i64       = 0;
            guard parse_challenge_params(clean, idx, challenge_b64, temp_token_key, temp_max_age) else {
                return false;
            }
            var raw_challenge: u8[..512] = [];
            var temp_chal = TokenChallenge { .. };
            if !matched &&
                core::base64url_decode(challenge_b64[..], raw_challenge) &&
                unmarshal_token_challenge(raw_challenge[..], temp_chal) &&
                temp_chal.token_type != 0 {
                best_chal = temp_chal;
                best_key = temp_token_key;
                best_age = temp_max_age;
                matched = true;
            }
        } else {
            if idx < clean.len && clean[idx] == ',' {
                guard consume_challenge_param_delimiter(clean, idx) else { return false; }
            } else {
                guard idx < clean.len && core::is_lws(clean[idx]) else { return false; }
                idx = core::add_sat_i64(idx, 1);
                guard skip_other_auth_challenge_params(clean, idx) else { return false; }
            }
        }
    }

    guard matched && can_fit(out_token_key, best_key.len) else { return false; }
    out_token_key.clear();
    out_token_key.append(best_key[..]);
    out_max_age_sec = best_age;
    out_challenge = best_chal;
    return true;
}

// Encodes binary bytes as RFC 4648 Section 5 base64url with mandatory '=' padding.
fn encode_padded_base64url<B>(data: const u8[:], out: B&) {
    let start_len = out.len;
    core::base64url_encode(data, out);
    let rem = core::sub_sat_i64(out.len, start_len) & 3;
    if rem == 2 {
        out.append("==");
    } else if rem == 3 {
        out.push('=' as u8);
    }
}

// Formats `Authorization: PrivateToken token="..."` header.
fn format_private_token_authorization<B>(token_bytes: const u8[:], out: B&) {
    // RFC 9577 Section 2.2.2: Sending Tokens - The token base64url value MUST include padding.
    out.clear();
    out.append("PrivateToken token=\"");
    encode_padded_base64url(token_bytes, out);
    out.push('"' as u8);
}

// Formats W3C `Sec-Private-State-Token` header with padded base64url.
fn format_sec_private_state_token<B>(token_bytes: const u8[:], out: B&) {
    out.clear();
    encode_padded_base64url(token_bytes, out);
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

inline fn header_contains_private_token_scheme(raw: const u8[:]) -> bool {
    let clean = raw.trim_lws();
    let scheme_len = rfc::SCHEME_PRIVATE_TOKEN.len;
    if clean.len >= scheme_len && clean[..scheme_len].eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) {
        if clean.len == scheme_len || core::is_lws(clean[scheme_len]) || clean[scheme_len] == ',' {
            return true;
        }
    }
    var chal = TokenChallenge { .. };
    var key: u8[..512] = [];
    var age: i64       = 0;
    return parse_private_token_challenge(clean, chal, key, age);
}

// Checks whether an HTTP response has a PrivateToken challenge.
fn has_private_token_challenge<Res>(res: const Res&) -> bool {
    guard res.status_code == rfc::STATUS_UNAUTHORIZED else { return false; }
    for &e in res.headers.entries {
        guard entry_name(res.headers, e).eq_ascii_fold("WWW-Authenticate") else { continue; }
        if header_contains_private_token_scheme(entry_value(res.headers, e)) {
            return true;
        }
    }
    return false;
}
