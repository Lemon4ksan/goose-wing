// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for Privacy Pass (RFC 9577) challenge parsing and token cache lookup.
namespace security_internal;

import std;
import core;
import rfc.http;
import .policy_internal;

// ---- Privacy Pass (RFC 9577) internal helpers ------------------------------

enum Token68SkipResult {
    NotToken68,
    Skipped,
    Invalid,
}

// RFC 9577 Section 2.1.1.1: Server Name Encoding - Authority host[:port] without userinfo, path, or whitespace.
inline fn is_valid_privacypass_server_name(s: const u8[:]) -> bool {
    guard s.len > 0 && core::find_byteset(s, "@/?#\\ \t,") < 0 && core::swar_find_ctl(s) == s.len else {
        return false;
    }
    var probe: u8[..272] = "https://";
    guard probe.try_append(s) else { return false; }
    return security::extract_hostname_from_origin(probe[..]).len > 0;
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

inline fn is_valid_quoted_pair_byte(b: u8) -> bool {
    return b == '\t' || b == ' ' || (b >= 0x21 && b <= 0x7E) || b >= 0x80;
}

inline fn is_valid_qdtext_byte(b: u8) -> bool {
    return b == '\t' || b == ' ' || b == 0x21 || (b >= 0x23 && b <= 0x5B) ||
        (b >= 0x5D && b <= 0x7E) || b >= 0x80;
}

// Scans an RFC 9110 Section 5.6.4 quoted-string starting at `quoted[0] == '"'`.
// Writes unescaped payload into `out` and returns consumed byte count including both quotes.
//
// Example:
//   quoted = "\"a\\\"b\", next"
//   returns: consumed = 6, ok = true, out = "a\"b"
inline fn decode_auth_quoted_string<B>(quoted: const u8[:], out: B&) -> i64, bool {
    guard quoted.len >= 2 && quoted[0] == '"' else { return 0, false; }
    var committed = false;
    defer if !committed { out.clear(); };

    out.clear();
    var pos: i64 = 1;
    while pos < quoted.len {
        let b = quoted[pos];
        if b == '"' {
            committed = true;
            return core::add_sat_i64(pos, 1), true;
        }
        if b == '\\' {
            pos = core::add_sat_i64(pos, 1);
            guard pos < quoted.len && is_valid_quoted_pair_byte(quoted[pos]) else { return 0, false; }
            guard out.try_push(quoted[pos]) else { return 0, false; }
        } else {
            guard is_valid_qdtext_byte(b) && out.try_push(b) else { return 0, false; }
        }
        pos = core::add_sat_i64(pos, 1);
    }
    return 0, false;
}

// Extracts parameter value from key-value parameter string into `out`.
// Leaves `idx` and `out` unchanged on error.
//
// Example:
//   rem = "= \"abc\", def", idx = 0
//   returns: true, idx = 7, out = "abc"
fn parse_param_val<B>(rem: const u8[:], idx: i64&, out: B&) -> bool {
    guard idx >= 0 && idx <= rem.len else { return false; }
    let saved_idx = idx;
    let saved_len = out.len;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        out.resize(saved_len);
    };

    let after_key = rem[idx..].trim_lws_start();
    guard after_key.len > 0 && after_key[0] == '=' else { return false; }
    let after_eq = after_key[1..].trim_lws_start();
    guard after_eq.len > 0 else { return false; }

    let v_start = core::sub_sat_i64(rem.len, after_eq.len);
    if after_eq[0] == '"' {
        let consumed_q, ok_q = decode_auth_quoted_string(after_eq, out);
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
    guard is_valid_cors_token(val) && out.try_set(val) else { return false; }
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
    guard idx >= 0 && idx <= raw.len else { return false; }
    let saved_idx = idx;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        challenge_b64.clear();
        temp_token_key.clear();
        temp_max_age = 0;
    };

    challenge_b64.clear();
    temp_token_key.clear();
    temp_max_age = 0;

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

inline fn try_skip_token68_challenge_param(
    raw:      const u8[:],
    rem_init: const u8[:],
    idx:      i64&,
) -> Token68SkipResult {
    let first_tok = read_param_key(rem_init);
    let after_first = rem_init[first_tok.len..].trim_lws_start();
    let tok68_cand = rem_init[..core::sub_sat_i64(rem_init.len, after_first.len)].trim_lws_end();
    let is_tok68 = after_first.len == 0 || (after_first[0] == ',' && is_valid_token68_slice(tok68_cand));
    guard is_tok68 else { return Token68SkipResult.NotToken68; }
    let tok68_end = core::find_byteset(rem_init, ", \t");
    let tlen = if tok68_end >= 0 { tok68_end } else { rem_init.len };
    guard is_valid_token68_slice(rem_init[..tlen]) else { return Token68SkipResult.Invalid; }
    idx = core::add_sat_i64(idx, tlen);
    return if consume_challenge_param_delimiter(raw, idx) {
        Token68SkipResult.Skipped
    } else {
        Token68SkipResult.Invalid
    };
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

    let tok68_res = try_skip_token68_challenge_param(raw, rem_init, idx);
    if tok68_res != Token68SkipResult.NotToken68 {
        return tok68_res == Token68SkipResult.Skipped;
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

fn find_free_token_slot(cache: const security::PrivateTokenCache&, now_sec: i64) -> i64, bool {
    var earliest_idx: i64 = 0;
    var earliest_exp: i64 = 9223372036854775807;
    for &entry, i in cache.entries {
        if entry.used || (entry.expires_at_sec > 0 && now_sec > entry.expires_at_sec) {
            return i, true;
        }
        if entry.expires_at_sec > 0 && entry.expires_at_sec < earliest_exp {
            earliest_exp = entry.expires_at_sec;
            earliest_idx = i;
        }
    }
    if cache.entries.len < cache.entries.cap {
        return 0, false;
    }
    return earliest_idx, true;
}

inline fn entry_matches_challenge(
    entry:   const security::CachedToken&,
    digest:  const u8[32]&,
    now_sec: i64,
) -> bool {
    guard !entry.used else { return false; }
    guard entry.expires_at_sec == 0 || now_sec <= entry.expires_at_sec else { return false; }
    // RFC 9577 Section 2.1.4: Token Caching - Cached tokens can only be redeemed when they match all of the fields in the TokenChallenge.
    return core::ct_eq_bytes(entry.challenge_digest[..], digest[..]);
}

inline fn header_contains_private_token_scheme(raw: const u8[:]) -> bool {
    let clean = raw.trim_lws();
    let scheme_len = rfc::SCHEME_PRIVATE_TOKEN.len;
    if clean.len >= scheme_len && clean[..scheme_len].eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) {
        if clean.len == scheme_len || core::is_lws(clean[scheme_len]) || clean[scheme_len] == ',' {
            return true;
        }
    }
    var key: u8[..512] = [];
    let _, _, ok = security::parse_private_token_challenge(clean, key);
    return ok;
}
