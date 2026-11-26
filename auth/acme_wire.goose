// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8555 ACME v2 wire codecs: RFC 7638 P-256 thumbprint, Flattened JWS ES256 signing,
// and structured JSON parsers for Directory, Order, and HTTP-01 Authorization objects.
namespace auth;

import std;
import json;
import core;
import .types;
import .internal;
import .oauth_internal;
import .jwk;
import .acme;

// ---- ACME Wire Types (RFC 8555 Section 7.1) --------------------------------

// RFC 8555 Section 7.1.1: Directory endpoints required for account and order management.
struct AcmeDirectory {
    new_nonce:   u8[..256] = [],
    new_account: u8[..256] = [],
    new_order:   u8[..256] = [],
}

// RFC 8555 Section 7.1.6: Status Changes - Order and Challenge lifecycle states.
enum AcmeOrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    Unknown,
}

// RFC 8555 Section 7.1.3: Order Objects - parsed order metadata and authorization URLs.
struct AcmeOrder {
    order_url:       u8[..256]       = [],
    status:          AcmeOrderStatus = AcmeOrderStatus.Unknown,
    authz_urls:      u8[..256][..8]  = [],
    finalize_url:    u8[..256]       = [],
    certificate_url: u8[..256]       = [],
}

// RFC 8555 Section 7.1.6: Status Changes - Authorization lifecycle states.
enum AcmeAuthzStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
    Unknown,
}

// RFC 8555 Section 7.1.5 / 8.3: HTTP-01 challenge metadata and precomputed key authorization.
struct AcmeHttp01Challenge {
    url:          u8[..256]       = [],
    token:        u8[..64]        = [],
    key_auth:     u8[..256]       = [],
    status:       AcmeOrderStatus = AcmeOrderStatus.Unknown,
    authz_status: AcmeAuthzStatus = AcmeAuthzStatus.Unknown,
}

// ---- Internal Key, URL, and Status Helpers ---------------------------------

inline fn acme_make_p256_jwk(priv_key: const u8[32]&) -> JwksKey, bool {
    guard core::is_valid_p256_private_key(priv_key) else { return JwksKey { .. }, false; }
    let pub_key = core::ecdsa_p256_public_key(priv_key);
    guard pub_key[0] == 0x04 else { return JwksKey { .. }, false; }
    var jwk = JwksKey {
        kty: JwkKeyType.EC,
        crv: "P-256",
        ..
    };
    guard jwk.ec_x.try_set(pub_key[1..33]) && jwk.ec_y.try_set(pub_key[33..65]) else {
        return JwksKey { .. }, false;
    }
    return jwk, true;
}

// RFC 8555 Section 6.5.1: Replay-Nonce MUST be an unpadded base64url token (`[A-Za-z0-9_-]+`).
inline fn is_valid_acme_replay_nonce(nonce: const u8[:]) -> bool {
    guard nonce.len > 0 && nonce.len <= 256 else { return false; }
    for b in nonce {
        guard core::is_ascii_alphanumeric(b) || b == '-' || b == '_' else { return false; }
    }
    return true;
}

inline fn is_valid_acme_http_url(url: const u8[:]) -> bool {
    guard url.len > 0 && url.len <= 256 else { return false; }
    guard core::swar_find_ctl(url) == url.len && !url.contains_byte(0x7F) &&
        !url.contains_byte(' ') && !url.contains_byte('\\') else {
        return false;
    }
    let parsed, err = core::parse_url(url);
    guard err == core::UrlParseError.None && parsed.hostname().len > 0 && !parsed.has_credentials() else {
        return false;
    }
    return parsed.scheme().eq_ascii_fold("https") || parsed.scheme().eq_ascii_fold("http");
}

// Parses an RFC 8555 Section 7.1.6 order status string, failing closed to `Unknown`.
//
// Example:
//   raw = "ready"
//   returns: AcmeOrderStatus.Ready
fn parse_acme_order_status(raw: const u8[:]) -> AcmeOrderStatus {
    if raw == "pending" { return AcmeOrderStatus.Pending; }
    if raw == "ready" { return AcmeOrderStatus.Ready; }
    if raw == "processing" { return AcmeOrderStatus.Processing; }
    if raw == "valid" { return AcmeOrderStatus.Valid; }
    if raw == "invalid" { return AcmeOrderStatus.Invalid; }
    return AcmeOrderStatus.Unknown;
}

// Parses an RFC 8555 Section 7.1.6 challenge status string, failing closed to `Unknown`.
//
// Example:
//   raw = "pending"
//   returns: AcmeOrderStatus.Pending
fn parse_acme_challenge_status(raw: const u8[:]) -> AcmeOrderStatus {
    if raw == "pending" { return AcmeOrderStatus.Pending; }
    if raw == "processing" { return AcmeOrderStatus.Processing; }
    if raw == "valid" { return AcmeOrderStatus.Valid; }
    if raw == "invalid" { return AcmeOrderStatus.Invalid; }
    return AcmeOrderStatus.Unknown;
}

// Parses an RFC 8555 Section 7.1.6 authorization status string, failing closed to `Unknown`.
//
// Example:
//   raw = "deactivated"
//   returns: AcmeAuthzStatus.Deactivated
fn parse_acme_authz_status(raw: const u8[:]) -> AcmeAuthzStatus {
    if raw == "pending" { return AcmeAuthzStatus.Pending; }
    if raw == "valid" { return AcmeAuthzStatus.Valid; }
    if raw == "invalid" { return AcmeAuthzStatus.Invalid; }
    if raw == "deactivated" { return AcmeAuthzStatus.Deactivated; }
    if raw == "expired" { return AcmeAuthzStatus.Expired; }
    if raw == "revoked" { return AcmeAuthzStatus.Revoked; }
    return AcmeAuthzStatus.Unknown;
}

inline fn read_acme_url_field<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
        return;
    }
    if !core::read_json_string_into(reader, dst) || !is_valid_acme_http_url(dst[..]) {
        had_err = true;
    }
}

inline fn mark_acme_key_seen(seen_mask: u32&, bit: u32, had_err: bool&) {
    if (seen_mask & bit) != 0 {
        had_err = true;
    }
    seen_mask = seen_mask | bit;
}

// ---- RFC 7638 Thumbprint & RFC 8555 §6.2 Flattened JWS ES256 Signing -------

// RFC 7638 Section 3: JSON Web Key (JWK) Thumbprint - writes 43-char Base64URL SHA-256 P-256 thumbprint to `out_b64`.
fn acme_jwk_thumbprint_p256(priv_key: const u8[32]&, out_b64: u8[..64]&) -> bool {
    out_b64.clear();
    let jwk, ok = acme_make_p256_jwk(priv_key);
    guard ok else { return false; }
    return compute_jwk_thumbprint(jwk, out_b64);
}

// Builds RFC 8555 Section 6.2 JWS Protected Header JSON (with `jwk` or `kid`, `nonce`, and `url`).
fn build_acme_protected_header_json(
    jwk:   const JwksKey&,
    url:   const u8[:],
    nonce: const u8[:],
    kid:   const u8[:],
    out:   u8[>..]&,
) -> bool {
    out.append("{\"alg\":\"ES256\",");
    if kid.len == 0 {
        var jwk_json: u8[..512] = [];
        guard compute_canonical_jwk(jwk, jwk_json) else { return false; }
        out.append("\"jwk\":");
        out.append(jwk_json[..]);
    } else {
        out.append("\"kid\":");
        core::format_json_string(out, kid);
    }
    out.append(",\"nonce\":");
    core::format_json_string(out, nonce);
    out.append(",\"url\":");
    core::format_json_string(out, url);
    out.push('}');
    return true;
}

// RFC 8555 Section 6.2: Request Authentication - signs `payload_json` (or POST-as-GET empty payload)
// as RFC 7515 Section 7.2.2 Flattened JWS JSON Serialization with ES256 into `out_jws`.
//
// Example:
//   url = "https://acme.example/new-acct", nonce = "n1", kid = "", payload_json = "{}"
//   returns: true, out_jws = "{\"protected\":\"...\",\"payload\":\"e30\",\"signature\":\"...\"}"
fn acme_sign_jws_es256(
    priv_key:     const u8[32]&,
    url:          const u8[:],
    nonce:        const u8[:],
    kid:          const u8[:],
    payload_json: const u8[:],
    out_jws:      u8[>..]&,
) -> bool {
    out_jws.clear();
    guard url.len > 0 && is_valid_acme_replay_nonce(nonce) else { return false; }
    guard url.validate_utf8() && kid.validate_utf8() else { return false; }
    let jwk, ok_jwk = acme_make_p256_jwk(priv_key);
    guard ok_jwk else { return false; }

    var prot_json: u8[>..] = [];
    guard build_acme_protected_header_json(jwk, url, nonce, kid, prot_json) else { return false; }

    var signing_input: u8[>..] = [];
    core::base64url_encode(prot_json[..], signing_input);
    let prot_b64_len = signing_input.len;
    signing_input.push('.');
    if payload_json.len > 0 {
        core::base64url_encode(payload_json, signing_input);
    }
    let pay_b64_start = core::add_sat_i64(prot_b64_len, 1);

    // RFC 8555 Section 6.2: ES256 signs UTF-8 bytes of ASCII(protected_b64 || "." || payload_b64).
    let raw_sig = core::ecdsa_p256_sign(priv_key, signing_input[..]);
    var sig_b64: u8[..128] = [];
    core::base64url_encode(raw_sig[..], sig_b64);

    // RFC 7515 Section 7.2.2: Flattened JWS JSON Serialization Syntax.
    var jws_buf: u8[>..] = [];
    jws_buf.append("{\"protected\":\"");
    jws_buf.append(signing_input[..prot_b64_len]);
    jws_buf.append("\",\"payload\":\"");
    jws_buf.append(signing_input[pay_b64_start..]);
    jws_buf.append("\",\"signature\":\"");
    jws_buf.append(sig_b64[..]);
    jws_buf.append("\"}");
    out_jws.append(jws_buf[..]);
    return true;
}

// ---- RFC 8555 JSON Resource Parsers ----------------------------------------

// Parses one member of an RFC 8555 Section 7.1.1 Directory JSON object.
//
// Example:
//   key = "newNonce", reader at "\"https://ex/n\""
//   sets: dir.new_nonce = "https://ex/n", seen_mask |= 1
inline fn parse_acme_directory_member(
    key:       const u8[:],
    reader:    json::Reader&,
    dir:       AcmeDirectory&,
    seen_mask: u32&,
    had_err:   bool&,
) {
    if key.contains('\\') {
        had_err = true;
        json::skip(reader);
        return;
    }
    if key == "newNonce" {
        mark_acme_key_seen(seen_mask, 1, had_err);
        read_acme_url_field(reader, dir.new_nonce, had_err);
        return;
    }
    if key == "newAccount" {
        mark_acme_key_seen(seen_mask, 2, had_err);
        read_acme_url_field(reader, dir.new_account, had_err);
        return;
    }
    if key == "newOrder" {
        mark_acme_key_seen(seen_mask, 4, had_err);
        read_acme_url_field(reader, dir.new_order, had_err);
        return;
    }
    json::skip(reader);
}

// RFC 8555 Section 7.1.1: Directory - parses `newNonce`, `newAccount`, and `newOrder` URLs.
// Resets `out_dir` on error.
//
// Example:
//   raw_json = "{\"newNonce\":\"https://ex/n\",\"newAccount\":\"https://ex/a\",\"newOrder\":\"https://ex/o\"}"
//   returns: true, out_dir populated
fn acme_parse_directory(raw_json: const u8[:], out_dir: AcmeDirectory&) -> bool {
    out_dir = AcmeDirectory { .. };
    guard raw_json.validate_utf8() else { return false; }
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return false; }

    var dir = AcmeDirectory { .. };
    var seen_mask: u32 = 0;
    var had_err = false;
    json::each_member(reader) { key =>
        parse_acme_directory_member(key, reader, dir, seen_mask, had_err);
    };
    guard json::finish(reader) && !had_err && seen_mask == 7 else { return false; }
    out_dir = dir;
    return true;
}

// Parses the `"authorizations"` JSON URL array of an RFC 8555 Section 7.1.3 Order object.
//
// Example:
//   reader at "[\"https://ex/az/1\"]"
//   pushes: "https://ex/az/1" into ord.authz_urls
inline fn parse_acme_order_authz_array(reader: json::Reader&, ord: AcmeOrder&, had_err: bool&) {
    guard json::peek(reader) == '[' else {
        json::skip(reader);
        had_err = true;
        return;
    }
    json::each_element(reader) {
        var url_buf: u8[..256] = [];
        if json::peek(reader) != '"' {
            json::skip(reader);
            had_err = true;
        } else if !core::read_json_string_into(reader, url_buf) ||
            !is_valid_acme_http_url(url_buf[..]) || !ord.authz_urls.try_push(url_buf) {
            had_err = true;
        }
    };
}

// Parses one member of an RFC 8555 Section 7.1.3 Order JSON object.
//
// Example:
//   key = "finalize", reader at "\"https://ex/fin\""
//   sets: ord.finalize_url = "https://ex/fin", seen_mask |= 4
inline fn parse_acme_order_member(
    key:       const u8[:],
    reader:    json::Reader&,
    ord:       AcmeOrder&,
    seen_mask: u32&,
    had_err:   bool&,
) {
    if key.contains('\\') {
        had_err = true;
        json::skip(reader);
        return;
    }
    if key == "status" {
        mark_acme_key_seen(seen_mask, 1, had_err);
        var st_buf: u8[..32] = [];
        if json::peek(reader) != '"' {
            json::skip(reader);
            had_err = true;
            return;
        }
        if !core::read_json_string_into(reader, st_buf) {
            had_err = true;
            return;
        }
        ord.status = parse_acme_order_status(st_buf[..]);
        if ord.status == AcmeOrderStatus.Unknown { had_err = true; }
        return;
    }
    if key == "authorizations" {
        mark_acme_key_seen(seen_mask, 2, had_err);
        parse_acme_order_authz_array(reader, ord, had_err);
        return;
    }
    if key == "finalize" {
        mark_acme_key_seen(seen_mask, 4, had_err);
        read_acme_url_field(reader, ord.finalize_url, had_err);
        return;
    }
    if key == "certificate" {
        mark_acme_key_seen(seen_mask, 8, had_err);
        if json::peek(reader) == 'n' {
            json::skip(reader);
        } else {
            read_acme_url_field(reader, ord.certificate_url, had_err);
        }
        return;
    }
    json::skip(reader);
}

// RFC 8555 Section 7.1.3: Order Objects - parses order `status`, `authorizations`, `finalize`, and `certificate`.
// Resets `out_ord` on error or unknown status.
//
// Example:
//   raw_json = "{\"status\":\"pending\",\"authorizations\":[\"https://ex/az/1\"],\"finalize\":\"https://ex/fin\"}"
//   returns: true, out_ord.status = AcmeOrderStatus.Pending
fn acme_parse_order(raw_json: const u8[:], out_ord: AcmeOrder&) -> bool {
    out_ord = AcmeOrder { .. };
    guard raw_json.validate_utf8() else { return false; }
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return false; }

    var ord = AcmeOrder { .. };
    var seen_mask: u32 = 0;
    var had_err = false;
    json::each_member(reader) { key =>
        parse_acme_order_member(key, reader, ord, seen_mask, had_err);
    };
    guard json::finish(reader) && !had_err && (seen_mask & 7) == 7 else { return false; }
    out_ord = ord;
    return true;
}

struct AcmeChallengeCandidate {
    ch_type:   u8[..32]        = [],
    type_ok:   bool            = false,
    url:       u8[..256]       = [],
    url_ok:    bool            = false,
    status:    AcmeOrderStatus = AcmeOrderStatus.Unknown,
    status_ok: bool            = false,
    token:     u8[..64]        = [],
    token_ok:  bool            = false,
    seen_mask: u32             = 0,
    had_err:   bool            = false,
}

inline fn read_challenge_type_field(reader: json::Reader&, cand: AcmeChallengeCandidate&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        cand.had_err = true;
        return;
    }
    let ok_str = core::read_json_string_into(reader, cand.ch_type);
    if ok_str && cand.ch_type.len == 0 {
        cand.had_err = true;
        return;
    }
    cand.type_ok = ok_str;
}

inline fn read_challenge_url_candidate(reader: json::Reader&, cand: AcmeChallengeCandidate&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        cand.url_ok = false;
        return;
    }
    cand.url_ok = core::read_json_string_into(reader, cand.url) && is_valid_acme_http_url(cand.url[..]);
}

inline fn read_challenge_status_candidate(reader: json::Reader&, cand: AcmeChallengeCandidate&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        cand.status_ok = false;
        return;
    }
    var st_buf: u8[..32] = [];
    if core::read_json_string_into(reader, st_buf) {
        cand.status = parse_acme_challenge_status(st_buf[..]);
        cand.status_ok = cand.status != AcmeOrderStatus.Unknown;
    } else {
        cand.status_ok = false;
    }
}

inline fn read_challenge_token_candidate(reader: json::Reader&, cand: AcmeChallengeCandidate&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        cand.token_ok = false;
        return;
    }
    cand.token_ok = core::read_json_string_into(reader, cand.token);
}

// Parses one member of an RFC 8555 Section 7.1.5 Challenge JSON object without failing
// on sibling challenge token/url/status sizes or unknown sibling challenge statuses.
//
// Example:
//   key = "type", reader at "\"http-01\""
//   sets: cand.ch_type = "http-01", cand.seen_mask |= 1
inline fn parse_acme_challenge_member(
    key:    const u8[:],
    reader: json::Reader&,
    cand:   AcmeChallengeCandidate&,
) {
    if key.contains('\\') {
        cand.had_err = true;
        json::skip(reader);
        return;
    }
    if key == "type" {
        mark_acme_key_seen(cand.seen_mask, 1, cand.had_err);
        read_challenge_type_field(reader, cand);
        return;
    }
    if key == "url" {
        mark_acme_key_seen(cand.seen_mask, 2, cand.had_err);
        read_challenge_url_candidate(reader, cand);
        return;
    }
    if key == "status" {
        mark_acme_key_seen(cand.seen_mask, 4, cand.had_err);
        read_challenge_status_candidate(reader, cand);
        return;
    }
    if key == "token" {
        mark_acme_key_seen(cand.seen_mask, 8, cand.had_err);
        read_challenge_token_candidate(reader, cand);
        return;
    }
    json::skip(reader);
}

const ACME_AUTHZ_SEEN_STATUS:     u32 = 1;
const ACME_AUTHZ_SEEN_CHALLENGES: u32 = 2;
const ACME_AUTHZ_FOUND_HTTP01:    u32 = 4;
const ACME_AUTHZ_HAD_ERROR:       u32 = 8;

// Parses a single object from the `"challenges"` array, keeping the `"http-01"` challenge.
//
// Example:
//   reader at "{\"type\":\"http-01\",\"url\":\"https://ex/c\",\"status\":\"pending\",\"token\":\"<22+ chars>\"}"
//   sets: ACME_AUTHZ_FOUND_HTTP01 in state_mask, out_ch populated
inline fn parse_single_acme_challenge_obj(
    reader:     json::Reader&,
    thumbprint: const u8[:],
    out_ch:     AcmeHttp01Challenge&,
    state_mask: u32&,
) {
    guard json::peek(reader) == '{' else {
        json::skip(reader);
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        return;
    }
    var cand = AcmeChallengeCandidate { .. };
    json::each_member(reader) { key =>
        parse_acme_challenge_member(key, reader, cand);
    };
    if cand.had_err || (cand.seen_mask & 1) == 0 {
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        return;
    }
    if !cand.type_ok || cand.ch_type[..] != "http-01" {
        return;
    }
    if (state_mask & ACME_AUTHZ_FOUND_HTTP01) != 0 ||
        (cand.seen_mask & 15) != 15 ||
        !cand.url_ok ||
        !cand.status_ok ||
        !cand.token_ok {
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        return;
    }
    guard build_acme_key_authorization(cand.token[..], thumbprint, out_ch.key_auth) else {
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        return;
    }
    out_ch.url = cand.url;
    out_ch.token = cand.token;
    out_ch.status = cand.status;
    state_mask |= ACME_AUTHZ_FOUND_HTTP01;
}

inline fn read_acme_authz_status_field(
    reader:     json::Reader&,
    out_status: AcmeAuthzStatus&,
    state_mask: u32&,
) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        return;
    }
    var st_buf: u8[..32] = [];
    if !core::read_json_string_into(reader, st_buf) {
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        return;
    }
    out_status = parse_acme_authz_status(st_buf[..]);
    if out_status == AcmeAuthzStatus.Unknown {
        state_mask |= ACME_AUTHZ_HAD_ERROR;
    }
}

// Parses one member of an RFC 8555 Section 7.1.4 Authorization JSON object.
//
// Example:
//   key = "status", reader at "\"pending\""
//   sets: ACME_AUTHZ_SEEN_STATUS in state_mask, ch.authz_status = Pending
inline fn parse_acme_authz_member(
    key:        const u8[:],
    reader:     json::Reader&,
    thumbprint: const u8[:],
    ch:         AcmeHttp01Challenge&,
    state_mask: u32&,
) {
    if key.contains('\\') {
        state_mask |= ACME_AUTHZ_HAD_ERROR;
        json::skip(reader);
        return;
    }
    if key == "status" {
        if (state_mask & ACME_AUTHZ_SEEN_STATUS) != 0 { state_mask |= ACME_AUTHZ_HAD_ERROR; }
        state_mask |= ACME_AUTHZ_SEEN_STATUS;
        read_acme_authz_status_field(reader, ch.authz_status, state_mask);
        return;
    }
    if key == "challenges" {
        if (state_mask & ACME_AUTHZ_SEEN_CHALLENGES) != 0 || json::peek(reader) != '[' {
            json::skip(reader);
            state_mask |= ACME_AUTHZ_HAD_ERROR;
            return;
        }
        state_mask |= ACME_AUTHZ_SEEN_CHALLENGES;
        json::each_element(reader) {
            parse_single_acme_challenge_obj(reader, thumbprint, ch, state_mask);
        };
        return;
    }
    json::skip(reader);
}

// RFC 8555 Section 7.1.4 / Section 8.3: Authorization Objects - extracts the HTTP-01 challenge
// and derives `key_auth = "<token>.<thumbprint>"`. Resets `out_ch` on error.
//
// Example:
//   raw_json = "{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://ex/c\",\"status\":\"pending\",\"token\":\"<22+ chars>\"}]}"
//   returns: true, out_ch populated
fn acme_parse_authz_http01(
    raw_json:   const u8[:],
    thumbprint: const u8[:],
    out_ch:     AcmeHttp01Challenge&,
) -> bool {
    out_ch = AcmeHttp01Challenge { .. };
    guard auth_internal::is_valid_acme_thumbprint(thumbprint) && raw_json.validate_utf8() else {
        return false;
    }
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return false; }

    var ch = AcmeHttp01Challenge { .. };
    var state_mask: u32 = 0;
    json::each_member(reader) { key =>
        parse_acme_authz_member(key, reader, thumbprint, ch, state_mask);
    };
    let want_mask = ACME_AUTHZ_SEEN_STATUS | ACME_AUTHZ_SEEN_CHALLENGES | ACME_AUTHZ_FOUND_HTTP01;
    guard json::finish(reader) && (state_mask & (want_mask | ACME_AUTHZ_HAD_ERROR)) == want_mask else {
        return false;
    }
    out_ch = ch;
    return true;
}
