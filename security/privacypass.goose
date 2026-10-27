// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9576 Privacy Pass Architecture, RFC 9577 PrivateToken HTTP Authentication,
// and RFC 9578 Blind RSA Token Issuance for anti-bot WAF bypass and privacy authorization.
// Zero-heap binary wire serialization, challenge parsing, redemption caching, and header codecs.
namespace wing;

import std;
import core from "..";

// ---- 1. Privacy Pass Constants & Token Types --------------------------------

const SCHEME_PRIVATE_TOKEN: const u8[:] = "PrivateToken";
const HEADER_SEC_PRIVATE_STATE_TOKEN: const u8[:] = "Sec-Private-State-Token";

const TOKEN_TYPE_BLIND_RSA: u16 = 0x0001;           // RFC 9578 Blind RSA
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

// ---- 2. Data Structures -----------------------------------------------------

struct TokenChallenge {
    token_type: u16 = TOKEN_TYPE_BLIND_RSA,
    issuer_name: u8[..128] = [],
    redemption_context: u8[..32] = [],
    origin_info: u8[..256] = [],
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
    token_key_id: u8[..32] = [],
    authenticator: u8[..256] = [],
}

struct CachedToken {
    challenge_digest: u8[32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    token: Token = Token { .. },
    raw_token: u8[..512] = [],
    expires_at_sec: i64 = 0,
    used: bool = false,
}

struct PrivateTokenCache {
    entries: CachedToken[..16] = [],
}

// ---- 3. Wire Binary Marshaling & Unmarshaling (RFC 9577 §2.1.1 & §2.2.1) ----

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
    out.issuer_name.clear();
    out.redemption_context.clear();
    out.origin_info.clear();

    guard data.len >= 7 else { return false; } // 2 + 2 + 0 + 1 + 0 + 2 + 0

    let tt = ((data[0] << 8) | data[1]) as u16;
    out.token_type = tt;

    let iss_len = (((data[2] << 8) | data[3]) as i64);
    guard iss_len <= out.issuer_name.cap else { return false; }
    guard data.len >= 4 + iss_len + 1 else { return false; }

    for i in iss_len {
        out.issuer_name.push(data[4 + i]);
    }

    var offset = 4 + iss_len;
    let ctx_len = data[offset] as i64;
    offset += 1;

    guard ctx_len == 0 || ctx_len == 32 else { return false; }
    guard ctx_len <= out.redemption_context.cap else { return false; }
    guard data.len >= offset + ctx_len + 2 else { return false; }

    for i in ctx_len {
        out.redemption_context.push(data[offset + i]);
    }
    offset += ctx_len;

    let orig_len = (((data[offset] << 8) | data[offset + 1]) as i64);
    offset += 2;

    guard orig_len <= out.origin_info.cap else { return false; }
    guard data.len >= offset + orig_len else { return false; }
    for i in orig_len {
        out.origin_info.push(data[offset + i]);
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

    out.token_type = (data[0] << 8) | data[1];

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

// ---- 4. HTTP Authentication Header Parsing & Formatting (RFC 9577 §2.1 & §2.2)

// Parses `WWW-Authenticate: PrivateToken challenge="<base64url>", ...` header.
fn parse_private_token_challenge(
    header_val: const u8[:],
    out_challenge: TokenChallenge&,
    out_token_key: u8[..128]&,
    out_max_age_sec: i64&,
) -> bool {
    out_token_key.clear();
    out_max_age_sec = 0;

    // Must start with "PrivateToken"
    guard header_val.len > SCHEME_PRIVATE_TOKEN.len else { return false; }
    guard eq_ascii_fold(header_val[..SCHEME_PRIVATE_TOKEN.len], SCHEME_PRIVATE_TOKEN) else { return false; }

    var params_str = header_val[SCHEME_PRIVATE_TOKEN.len..];
    while params_str.len > 0 && (params_str[0] == ' ' || params_str[0] == '\t') {
        params_str = params_str[1..];
    }

    var challenge_b64: u8[..512] = [];

    // Parse comma-separated key=value pairs
    var idx = 0;
    while idx < params_str.len {
        while idx < params_str.len && (params_str[idx] == ' ' || params_str[idx] == '\t' || params_str[idx] == ',') {
            idx += 1;
        }
        guard idx < params_str.len else { break; }

        var k_start = idx;
        while idx < params_str.len && params_str[idx] != '=' && params_str[idx] != ',' && params_str[idx] != ' ' {
            idx += 1;
        }
        let key = params_str[k_start..idx];

        while idx < params_str.len && (params_str[idx] == ' ' || params_str[idx] == '=') {
            idx += 1;
        }

        var val_start = idx;
        var in_quotes = false;
        if idx < params_str.len && params_str[idx] == '"' {
            in_quotes = true;
            idx += 1;
            val_start = idx;
            while idx < params_str.len && params_str[idx] != '"' {
                idx += 1;
            }
            guard idx < params_str.len && params_str[idx] == '"' else { return false; }
        } else {
            while idx < params_str.len && params_str[idx] != ',' && params_str[idx] != ' ' {
                idx += 1;
            }
        }
        let val = params_str[val_start..idx];
        if in_quotes {
            idx += 1; // skip closing quote
        }

        if eq_ascii_fold(key, "challenge") {
            guard val.len <= challenge_b64.cap else { return false; }
            challenge_b64.clear();
            challenge_b64.append(val);
        } else if eq_ascii_fold(key, "token-key") {
            var raw_key: u8[>..] = [];
            if core::base64url_decode(val, raw_key) {
                guard raw_key.len <= out_token_key.cap else { return false; }
                for b in raw_key {
                    out_token_key.push(b);
                }
            } else {
                return false;
            }
        } else if eq_ascii_fold(key, "max-age") {
            var secs: i64 = 0;
            for b in val {
                if b >= '0' && b <= '9' {
                    secs = secs * 10 + (b - '0');
                }
            }
            out_max_age_sec = secs;
        }
    }

    guard challenge_b64.len > 0 else { return false; }
    var raw_challenge: u8[>..] = [];
    guard core::base64url_decode(challenge_b64[..], raw_challenge) else { return false; }

    return unmarshal_token_challenge(raw_challenge[..], out_challenge);
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

// ---- 5. Private Token Cache & Redemption Management -------------------------

// Puts a pre-issued or blinded token into cache for a challenge.
fn put_private_token(
    cache: PrivateTokenCache&,
    challenge: const TokenChallenge&,
    token: const Token&,
    raw_token: const u8[:],
    ttl_sec: i64,
    now_sec: i64,
) -> bool {
    let digest = compute_challenge_digest(challenge);

    // Look for existing or free slot
    var target_idx = -1;
    for i in cache.entries.len {
        if cache.entries[i].used || (cache.entries[i].expires_at_sec > 0 && now_sec > cache.entries[i].expires_at_sec) {
            target_idx = i;
            break;
        }
    }

    if target_idx == -1 {
        if cache.entries.len < cache.entries.cap {
            target_idx = cache.entries.len;
            cache.entries.push(CachedToken { .. });
        } else {
            target_idx = 0; // Evict slot 0
        }
    }

    cache.entries[target_idx].challenge_digest = digest;
    cache.entries[target_idx].token = token;
    cache.entries[target_idx].raw_token.clear();
    cache.entries[target_idx].raw_token.append(raw_token);
    cache.entries[target_idx].expires_at_sec = if ttl_sec > 0 { now_sec + ttl_sec } else { 0 };
    cache.entries[target_idx].used = false;

    return true;
}

// Gets and consumes a single-use token matching the challenge (RFC 9577 §2.1.4 single-spend).
fn get_private_token(
    cache: PrivateTokenCache&,
    challenge: const TokenChallenge&,
    now_sec: i64,
    out_token: Token&,
    out_raw: u8[..512]&,
) -> bool {
    let digest = compute_challenge_digest(challenge);

    for i in cache.entries.len {
        if !cache.entries[i].used {
            if cache.entries[i].expires_at_sec == 0 || now_sec <= cache.entries[i].expires_at_sec {
                // Check if digest matches
                var match_digest = true;
                for k in 32 {
                    if cache.entries[i].challenge_digest[k] != digest[k] {
                        match_digest = false;
                        break;
                    }
                }
                if match_digest {
                    out_token = cache.entries[i].token;
                    out_raw.clear();
                    out_raw.append(cache.entries[i].raw_token[..]);
                    cache.entries[i].used = true; // Single-use spend
                    return true;
                }
            }
        }
    }

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
