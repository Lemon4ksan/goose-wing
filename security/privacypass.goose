// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9576 Privacy Pass Architecture, RFC 9577 PrivateToken HTTP Authentication,
// and RFC 9578 Blind RSA Token Issuance for anti-bot WAF bypass and privacy authorization.
// Zero-heap binary wire serialization, challenge parsing, redemption caching, and header codecs.
namespace wing;

import std;
import core from "..";

// ---- Privacy Pass Constants & Token Types --------------------------------

const SCHEME_PRIVATE_TOKEN:           const u8[:] = "PrivateToken";
const HEADER_SEC_PRIVATE_STATE_TOKEN: const u8[:] = "Sec-Private-State-Token";

const TOKEN_TYPE_BLIND_RSA:           u16 = 0x0001; // RFC 9578 Blind RSA
const TOKEN_TYPE_PUBLICLY_VERIFIABLE: u16 = 0x0002; // RFC 9578 §6 Publicly Verifiable

// Checks whether token type is a GREASE identifier (RFC 9577 §6.2.1)
fn is_grease_token_type(t: u16) -> bool {
    let grease_types: const u16[17] = [
        0x0000, 0x02AA, 0x1132, 0x2E96, 0x3CD3, 0x4473, 0x5A63, 0x6D32,
        0x7F3F, 0x8D07, 0x916B, 0xA6A4, 0xBEAB, 0xC3F3, 0xDA42, 0xE944, 0xF057,
    ];
    for g in grease_types {
        if t == g { return true; }
    }
    return false;
}

// ---- Data Structures -----------------------------------------------------

struct TokenChallenge {
    token_type:         u16       = TOKEN_TYPE_BLIND_RSA,
    issuer_name:        u8[..128] = [],
    redemption_context: u8[..32]  = [],
    origin_info:        u8[..256] = [],
}

struct Token {
    token_type: u16 = TOKEN_TYPE_BLIND_RSA,
    nonce: u8[32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    challenge_digest: u8[32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    token_key_id:  u8[..32]  = [],
    authenticator: u8[..256] = [],
}

struct CachedToken {
    challenge_digest: u8[32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    token:          Token     = Token { .. },
    raw_token:      u8[..512] = [],
    expires_at_sec: i64       = 0,
    used:           bool      = false,
}

struct PrivateTokenCache {
    entries: CachedToken[..16] = [],
}

// ---- Wire Binary Marshaling & Unmarshaling (RFC 9577 §2.1.1 & §2.2.1) ----

// Marshals TokenChallenge into RFC 9577 §2.1.1 wire presentation format:
// token_type(2) + issuer_len(2) + issuer + ctx_len(1) + ctx + origin_len(2) + origin
fn marshal_token_challenge<B>(challenge: const TokenChallenge&, out: B&) {
    out.clear();
    let tt = challenge.token_type;
    out.push(((tt >> 8) & 0xFF) as u8);
    out.push((tt & 0xFF) as u8);

    let iss_len = challenge.issuer_name.len as u16;
    out.push(((iss_len >> 8) & 0xFF) as u8);
    out.push((iss_len & 0xFF) as u8);
    out.append(challenge.issuer_name[..]);

    let ctx_len = challenge.redemption_context.len as u8;
    out.push(ctx_len);
    out.append(challenge.redemption_context[..]);

    let orig_len = challenge.origin_info.len as u16;
    out.push(((orig_len >> 8) & 0xFF) as u8);
    out.push((orig_len & 0xFF) as u8);
    out.append(challenge.origin_info[..]);
}

// Unmarshals TokenChallenge from RFC 9577 §2.1.1 binary wire representation.
fn unmarshal_token_challenge(data: const u8[:], out: TokenChallenge&) -> bool {
    guard data.len >= 7 else { return false; } // 2 + 2 + 0 + 1 + 0 + 2 + 0

    let iss_len = (data[2] as i64 << 8) | data[3];
    guard iss_len <= out.issuer_name.cap else { return false; }
    guard data.len >= 4 + iss_len + 3 else { return false; }

    let offset1 = 4 + iss_len;
    let ctx_len = data[offset1] as i64;
    guard ctx_len == 0 || ctx_len == 32 else { return false; }
    guard ctx_len <= out.redemption_context.cap else { return false; }

    let offset2 = offset1 + 1 + ctx_len;
    guard data.len >= offset2 + 2 else { return false; }
    let orig_len = (data[offset2] as i64 << 8) | data[offset2 + 1];
    guard orig_len <= out.origin_info.cap else { return false; }
    guard data.len >= offset2 + 2 + orig_len else { return false; }

    out.token_type = ((data[0] as u16) << 8) | data[1];
    out.issuer_name.clear();
    out.issuer_name.append(data[4..4 + iss_len]);

    out.redemption_context.clear();
    if ctx_len > 0 {
        out.redemption_context.append(data[offset1 + 1..offset1 + 1 + ctx_len]);
    }

    out.origin_info.clear();
    if orig_len > 0 {
        out.origin_info.append(data[offset2 + 2..offset2 + 2 + orig_len]);
    }

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
    let tt = token.token_type;
    out.push(((tt >> 8) & 0xFF) as u8);
    out.push((tt & 0xFF) as u8);

    out.append(token.nonce[..]);
    out.append(token.challenge_digest[..]);
    out.append(token.token_key_id[..]);
    out.append(token.authenticator[..]);
}

// Unmarshals Token from RFC 9577 §2.2.1 binary representation.
fn unmarshal_token(data: const u8[:], key_id_len: i64, auth_len: i64, out: Token&) -> bool {
    guard key_id_len >= 0 && auth_len >= 0 else { return false; }
    guard key_id_len <= out.token_key_id.cap && auth_len <= out.authenticator.cap else { return false; }
    let expected_len = 2 + 32 + 32 + key_id_len + auth_len;
    guard data.len >= expected_len else { return false; }

    out.token_type = ((data[0] as u16) << 8) | data[1];

    for i in 32 {
        out.nonce[i] = data[2 + i];
    }
    for i in 32 {
        out.challenge_digest[i] = data[34 + i];
    }

    out.token_key_id.clear();
    var offset = 66;
    for i in key_id_len {
        out.token_key_id.push(data[offset + i]);
    }
    offset += key_id_len;

    out.authenticator.clear();
    for i in auth_len {
        out.authenticator.push(data[offset + i]);
    }

    return true;
}

// ---- HTTP Authentication Header Parsing & Formatting (RFC 9577 §2.1 & §2.2)

// Extracts parameter value from key-value parameter string.
//
// Example:
//   rem = "= \"abc\", def", idx = 0
//   returns: "abc", ok = true, idx = 7
fn parse_param_val(rem: const u8[:], idx: i64&) -> const u8[:], bool {
    while idx < rem.len && (rem[idx] == ' ' || rem[idx] == '=') {
        idx += 1;
    }
    guard idx < rem.len else { return "", false; }
    if rem[idx] == '"' {
        idx += 1;
        let v_start = idx;
        let rel_q = core::index_of_byte(rem[v_start..], '"');
        guard rel_q >= 0 else { return "", false; }
        let val = rem[v_start..v_start + rel_q];
        idx = v_start + rel_q + 1;
        return val, true;
    }
    let v_start = idx;
    while idx < rem.len && rem[idx] != ',' && rem[idx] != ' ' && rem[idx] != '\t' {
        idx += 1;
    }
    return rem[v_start..idx], true;
}

// Decodes base64url-encoded token-key parameter into buffer.
//
// Example:
//   val = "ZXhhbXBsZQ"
//   returns: ok = true, temp_token_key = "example"
fn decode_token_key_param(val: const u8[:], temp_token_key: u8[..128]&) -> bool {
    var raw_key: u8[>..] = [];
    guard core::base64url_decode(val, raw_key) else { return false; }
    guard raw_key.len <= temp_token_key.cap else { return false; }
    temp_token_key.clear();
    for b in raw_key {
        temp_token_key.push(b);
    }
    return true;
}

fn apply_challenge_param(
    key:            const u8[:],
    val:            const u8[:],
    temp_token_key: u8[..128]&,
    temp_max_age:   i64&,
) -> const u8[:], bool {
    if eq_ascii_fold(key, "challenge") {
        return val, true;
    }
    if eq_ascii_fold(key, "token-key") {
        guard decode_token_key_param(val, temp_token_key) else { return "", false; }
        return "", true;
    }
    if eq_ascii_fold(key, "max-age") {
        let secs, ok_sec = val.parse_i64_dec();
        if ok_sec && secs >= 0 {
            temp_max_age = secs;
        }
        return "", true;
    }
    return "", true;
}

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
    guard header_val.len > SCHEME_PRIVATE_TOKEN.len else { return false; }
    guard eq_ascii_fold(header_val[..SCHEME_PRIVATE_TOKEN.len], SCHEME_PRIVATE_TOKEN) else { return false; }

    var temp_token_key: u8[..128] = [];
    var temp_max_age:   i64       = 0;
    let challenge_slice, ok_params = parse_challenge_params(
        header_val[SCHEME_PRIVATE_TOKEN.len..].trim_lws(),
        temp_token_key,
        temp_max_age,
    );
    guard ok_params else { return false; }

    var raw_challenge: u8[>..] = [];
    guard core::base64url_decode(challenge_slice, raw_challenge) else { return false; }

    var temp_chal = TokenChallenge { .. };
    guard unmarshal_token_challenge(raw_challenge[..], temp_chal) else { return false; }

    // Commit only on complete success
    out_token_key.clear();
    for b in temp_token_key {
        out_token_key.push(b);
    }
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
    entry.expires_at_sec = if ttl_sec > 0 { now_sec + ttl_sec } else { 0 };
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
    guard res.status_code == 401 else { return false; }
    for idx in res.headers.len {
        if core::eq_ascii_fold(res.headers[idx].name[..], "WWW-Authenticate") {
            if core::contains(res.headers[idx].value[..], SCHEME_PRIVATE_TOKEN) {
                return true;
            }
        }
    }
    return false;
}
