// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9576 Privacy Pass Architecture, RFC 9577 PrivateToken HTTP Authentication,
// and RFC 9578 Blind RSA Token Issuance for anti-bot WAF bypass and privacy authorization.
// Zero-heap binary wire serialization, challenge parsing, redemption caching, and header codecs.
namespace security;

import std;
import core;
import rfc.http;
import .crypto_internal;
import .policy_internal;
import .privacypass_internal;

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
// token_type(2) + issuer_len(2) + issuer + ctx_len(1) + ctx + origin_len(2) + origin.
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
//
// Example:
//   data = [0x00,0x02, 0x00,0x0b, "issuer.test"..., 0x00, 0x00,0x00]
//   returns: TokenChallenge { token_type: 2, issuer_name: "issuer.test", .. }, true
fn unmarshal_token_challenge(data: const u8[:]) -> TokenChallenge, bool {
    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return TokenChallenge { .. }, false; }

    let iss, ok_iss = core::read_u16_prefixed(cur);
    guard ok_iss && security_internal::is_valid_privacypass_server_name(iss) else {
        return TokenChallenge { .. }, false;
    }

    let ctx, ok_ctx = core::read_u8_prefixed(cur);
    guard ok_ctx && (ctx.len == 0 || ctx.len == 32) else { return TokenChallenge { .. }, false; }

    let orig, ok_orig = core::read_u16_prefixed(cur);
    guard ok_orig && cur.buf.len == 0 && security_internal::is_valid_privacypass_origin_info(orig) else {
        return TokenChallenge { .. }, false;
    }

    var chal = TokenChallenge { token_type: token_type, .. };
    guard chal.issuer_name.try_set(iss) &&
        chal.redemption_context.try_set(ctx) &&
        chal.origin_info.try_set(orig) else {
        return TokenChallenge { .. }, false;
    }
    return chal, true;
}

// Computes SHA-256(TokenChallenge) as defined in RFC 9577 §2.2.1.
fn compute_challenge_digest(challenge: const TokenChallenge&) -> u8[32] {
    var raw: u8[..512] = [];
    marshal_token_challenge(challenge, raw);
    return core::sha256(raw[..]);
}

// Marshals Token into RFC 9577 §2.2.1 wire format:
// token_type(2) + nonce(32) + challenge_digest(32) + key_id(Nid) + authenticator(Nk).
fn marshal_token<B>(token: const Token&, out: B&) {
    out.clear();
    out.append_u16_be(token.token_type);
    out.append(token.nonce[..]);
    out.append(token.challenge_digest[..]);
    out.append(token.token_key_id[..]);
    out.append(token.authenticator[..]);
}

// Unmarshals Token from RFC 9577 §2.2.1 binary representation.
//
// Example:
//   data = wire_bytes, key_id_len = 32, auth_len = 64
//   returns: Token { .. }, true
fn unmarshal_token(data: const u8[:], key_id_len: i64, auth_len: i64) -> Token, bool {
    guard key_id_len > 0 && key_id_len <= 32 && auth_len > 0 && auth_len <= 256 else {
        return Token { .. }, false;
    }

    var cur = core::cursor_from(data);
    let token_type, ok_tt = core::read_u16(cur);
    guard ok_tt else { return Token { .. }, false; }

    let nonce_slice, ok_n = core::read_bytes(cur, 32);
    let digest_slice, ok_d = core::read_bytes(cur, 32);
    let key_id_slice, ok_k = core::read_bytes(cur, key_id_len);
    let auth_slice, ok_a = core::read_bytes(cur, auth_len);
    guard ok_n && ok_d && ok_k && ok_a && cur.buf.len == 0 else {
        return Token { .. }, false;
    }

    var tok = Token { token_type: token_type, .. };
    guard tok.token_key_id.try_set(key_id_slice) && tok.authenticator.try_set(auth_slice) else {
        return Token { .. }, false;
    }

    core::ct_copy_bytes(tok.nonce[..], nonce_slice);
    core::ct_copy_bytes(tok.challenge_digest[..], digest_slice);
    return tok, true;
}

// ---- HTTP Authentication Header Parsing & Formatting (RFC 9577 §2.1 & §2.2)

// Parses `WWW-Authenticate: PrivateToken challenge="<base64url>", ...` header (including multi-challenge lists).
// Returns parsed `TokenChallenge`, `max_age_sec`, and `ok`; writes decoded `token-key` bytes into `out`.
//
// Example:
//   header_val = "PrivateToken challenge=\"AAIADmlzc3Vlci5leGFtcGxlAAAA\", token-key=\"ZXhhbXBsZQ==\""
//   returns: TokenChallenge { .. }, max_age_sec = 0, ok = true (out = "example")
fn parse_private_token_challenge<B>(header_val: const u8[:], out: B&) -> TokenChallenge, i64, bool {
    let clean = header_val.trim_lws();
    guard clean.len > 0 else { return TokenChallenge { .. }, 0, false; }

    var matched = false;
    var best_chal = TokenChallenge { .. };
    var best_key: u8[..512] = [];
    var best_age: i64       = 0;

    var idx: i64 = 0;
    while idx < clean.len {
        let rem = clean[idx..].trim_lws_start();
        idx = core::sub_sat_i64(clean.len, rem.len);
        guard idx < clean.len else { break; }

        let scheme = security_internal::read_param_key(rem);
        guard security_internal::is_valid_cors_token(scheme) else { return TokenChallenge { .. }, 0, false; }
        idx = core::add_sat_i64(idx, scheme.len);

        if scheme.eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) {
            guard idx < clean.len && core::is_lws(clean[idx]) else { return TokenChallenge { .. }, 0, false; }
            idx = core::add_sat_i64(idx, 1);
            var challenge_b64:  u8[..512] = [];
            var temp_token_key: u8[..512] = [];
            var temp_max_age:   i64       = 0;
            guard security_internal::parse_challenge_params(
                clean, idx, challenge_b64, temp_token_key, temp_max_age,
            ) else {
                return TokenChallenge { .. }, 0, false;
            }
            guard !matched else { continue; }
            var raw_challenge: u8[..512] = [];
            guard core::base64url_decode(challenge_b64[..], raw_challenge) else { continue; }
            let temp_chal, ok_uc = unmarshal_token_challenge(raw_challenge[..]);
            if ok_uc && temp_chal.token_type != 0 {
                best_chal = temp_chal;
                best_key = temp_token_key;
                best_age = temp_max_age;
                matched = true;
            }
        } else if idx < clean.len && clean[idx] == ',' {
            guard security_internal::consume_challenge_param_delimiter(clean, idx) else {
                return TokenChallenge { .. }, 0, false;
            }
        } else {
            guard idx < clean.len && core::is_lws(clean[idx]) else { return TokenChallenge { .. }, 0, false; }
            idx = core::add_sat_i64(idx, 1);
            guard security_internal::skip_other_auth_challenge_params(clean, idx) else {
                return TokenChallenge { .. }, 0, false;
            }
        }
    }

    guard matched && security_internal::can_fit(out, best_key.len) else {
        return TokenChallenge { .. }, 0, false;
    }
    out.clear();
    out.append(best_key[..]);
    return best_chal, best_age, true;
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
    var target_idx, found_slot = security_internal::find_free_token_slot(cache, now_sec);

    if !found_slot {
        target_idx = cache.entries.len;
        guard cache.entries.try_push(CachedToken { .. }) else { return false; }
    }

    let entry .= cache.entries[target_idx];
    guard entry.raw_token.try_set(raw_token) else { return false; }
    entry.challenge_digest = digest;
    entry.token = token;
    entry.expires_at_sec = if ttl_sec > 0 { core::add_sat_i64(now_sec, ttl_sec) } else { 0 };
    entry.used = false;
    return true;
}

// Gets and consumes a single-use token matching the challenge (RFC 9577 §2.1.4 single-spend).
fn get_private_token<B>(
    cache:     PrivateTokenCache&,
    challenge: const TokenChallenge&,
    now_sec:   i64,
    out:       B&,
) -> Token, bool {
    let digest = compute_challenge_digest(challenge);
    for &entry in cache.entries {
        if security_internal::entry_matches_challenge(entry, digest, now_sec) {
            guard out.try_set(entry.raw_token[..]) else { return Token { .. }, false; }
            entry.used = true;
            return entry.token, true;
        }
    }
    return Token { .. }, false;
}

// Pops and consumes a single-use token matching the challenge digest (RFC 9577 §2.1.4 single-spend).
fn pop_private_token<B>(
    cache:            PrivateTokenCache&,
    challenge_digest: const u8[32]&,
    now_sec:          i64,
    out:              B&,
) -> bool {
    for &entry in cache.entries {
        if security_internal::entry_matches_challenge(entry, challenge_digest, now_sec) {
            guard out.try_set(entry.raw_token[..]) else { return false; }
            entry.used = true;
            return true;
        }
    }
    return false;
}

// Attaches an Authorization: PrivateToken header to an outbound request.
fn attach_private_token<R>(req: R&, token_bytes: const u8[:]) {
    var auth_header: u8[..1024] = [];
    format_private_token_authorization(token_bytes, auth_header);
    req.set_header("Authorization", auth_header[..]);
}

// Checks whether an HTTP response has a PrivateToken challenge.
fn has_private_token_challenge<Res>(res: const Res&) -> bool {
    guard res.status_code == rfc::STATUS_UNAUTHORIZED else { return false; }
    for &e in res.headers.entries {
        guard res.headers.entry_name(e).eq_ascii_fold("WWW-Authenticate") else { continue; }
        if security_internal::header_contains_private_token_scheme(res.headers.entry_value(e)) {
            return true;
        }
    }
    return false;
}
