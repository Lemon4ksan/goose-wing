// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7009 OAuth 2.0 Token Revocation, RFC 7662 OAuth 2.0 Token Introspection,
// and RFC 6749 §2.3.1 `client_secret_basic` credential encoding/decoding.
namespace wing;

import std;
import json;
import core from "..";

enum TokenTypeHint {
    None,
    AccessToken,
    RefreshToken,
}

struct IntrospectionResponse {
    active:     bool           = false,
    scope:      u8[..256]      = [],
    client_id:  u8[..128]      = [],
    username:   u8[..128]      = [],
    token_type: u8[..32]       = [],
    sub:        u8[..128]      = [],
    iss:        u8[..128]      = [],
    jti:        u8[..128]      = [],
    aud:        u8[..128][..8] = [],
    exp:        i64            = -1,
    iat:        i64            = -1,
    nbf:        i64            = -1,
}

// Encodes an RFC 7009 §2.1 / RFC 7662 §2.1 `application/x-www-form-urlencoded` request body
// containing `token=<urlencoded>` and optional `&token_type_hint=<hint>`.
//
// Example:
//   token = "sec/ret+1", hint = TokenTypeHint.AccessToken
//   returns: ok = true, out = "token=sec%2Fret%2B1&token_type_hint=access_token"
fn encode_token_endpoint_form<B>(token: const u8[:], hint: TokenTypeHint, out: B&) -> bool {
    out.clear();
    guard token.len > 0 && token.len <= 256 else { return false; }
    var buf: u8[..1024] = [];
    buf.append("token=");
    guard core::append_form_urlencoded(token, buf) else { return false; }
    if hint == TokenTypeHint.AccessToken {
        buf.append("&token_type_hint=access_token");
    } else if hint == TokenTypeHint.RefreshToken {
        buf.append("&token_type_hint=refresh_token");
    }
    return out.try_set(buf[..]);
}

// Parses `"aud"` field (single string or array of strings) in an RFC 7662 introspection response.
//
// Example:
//   reader at "\"https://resource.example.org\""
//   returns: ok = true, out.aud[0] = "https://resource.example.org"
inline fn parse_introspection_aud(reader: json::Reader&, scratch: u8[>..]&, out: IntrospectionResponse&) -> bool {
    let p = json::peek(reader);
    if p == '"' {
        let s = json::read_string(reader, scratch);
        guard s.len > 0 && s.len <= 128 && out.aud.len < out.aud.cap else { return false; }
        var item: u8[..128] = [];
        item.append(s);
        out.aud.push(item);
        return true;
    }
    guard p == '[' else {
        json::skip(reader);
        return false;
    }
    var ok = true;
    json::each_element(reader) {
        if json::peek(reader) != '"' {
            json::skip(reader);
            ok = false;
        } else {
            scratch.clear();
            let s = json::read_string(reader, scratch);
            if s.len == 0 || s.len > 128 || out.aud.len >= out.aud.cap {
                ok = false;
            } else {
                var item: u8[..128] = [];
                item.append(s);
                out.aud.push(item);
            }
        }
    };
    return ok;
}

// Reads a JSON string member into `dst` for RFC 7662 introspection metadata.
//
// Example:
//   reader at "\"read write\""
//   sets: dst = "read write", had_err = false
inline fn parse_introspection_str_field<B>(reader: json::Reader&, scratch: u8[>..]&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
    } else if !dst.try_set(json::read_string(reader, scratch)) {
        had_err = true;
    }
}

// Reads a non-negative JSON integer timestamp for RFC 7662 introspection metadata (`exp`, `iat`, `nbf`).
//
// Example:
//   reader at "1700000000"
//   sets: dst = 1700000000, had_err = false
inline fn parse_introspection_int_field(reader: json::Reader&, dst: i64&, had_err: bool&) {
    let p = json::peek(reader);
    if p >= '0' && p <= '9' {
        dst = json::read_int(reader);
    } else {
        json::skip(reader);
        had_err = true;
    }
}

// Parses string metadata fields of an RFC 7662 Token Introspection Response JSON object.
//
// Example:
//   key = "client_id", reader at "\"l23\""
//   sets: out.client_id = "l23", returns: true
inline fn parse_introspection_str_member(
    key:     const u8[:],
    reader:  json::Reader&,
    scratch: u8[>..]&,
    out:     IntrospectionResponse&,
    had_err: bool&,
) -> bool {
    if key == "scope" { parse_introspection_str_field(reader, scratch, out.scope, had_err); return true; }
    if key == "client_id" { parse_introspection_str_field(reader, scratch, out.client_id, had_err); return true; }
    if key == "username" { parse_introspection_str_field(reader, scratch, out.username, had_err); return true; }
    if key == "token_type" { parse_introspection_str_field(reader, scratch, out.token_type, had_err); return true; }
    if key == "sub" { parse_introspection_str_field(reader, scratch, out.sub, had_err); return true; }
    if key == "iss" { parse_introspection_str_field(reader, scratch, out.iss, had_err); return true; }
    if key == "jti" { parse_introspection_str_field(reader, scratch, out.jti, had_err); return true; }
    return false;
}

// Parses a single field of an RFC 7662 §2.2 Token Introspection Response JSON object.
//
// Example:
//   key = "active", reader at "true"
//   sets: out.active = true, seen_active = true
inline fn parse_introspection_field(
    key:         const u8[:],
    reader:      json::Reader&,
    scratch:     u8[>..]&,
    out:         IntrospectionResponse&,
    seen_active: bool&,
    had_err:     bool&,
) {
    if key == "active" {
        let p = json::peek(reader);
        if seen_active || (p != 't' && p != 'f') {
            json::skip(reader);
            had_err = true;
        } else {
            out.active = json::read_bool(reader);
            seen_active = true;
        }
        return;
    }
    if parse_introspection_str_member(key, reader, scratch, out, had_err) { return; }
    if key == "aud" {
        if !parse_introspection_aud(reader, scratch, out) { had_err = true; }
        return;
    }
    if key == "exp" { parse_introspection_int_field(reader, out.exp, had_err); return; }
    if key == "iat" { parse_introspection_int_field(reader, out.iat, had_err); return; }
    if key == "nbf" { parse_introspection_int_field(reader, out.nbf, had_err); return; }
    json::skip(reader);
}

// Parses an RFC 7662 §2.2 Token Introspection Response JSON document.
// Requires `"active"` to be explicitly present as a JSON boolean and clears metadata when `active == false`.
//
// Example:
//   raw_json = "{\"active\":true,\"client_id\":\"l23\",\"sub\":\"Z5O\"}"
//   returns: out.active = true, out.client_id = "l23", ok = true
fn parse_introspection_response(raw_json: const u8[:]) -> IntrospectionResponse, bool {
    var out = IntrospectionResponse { .. };
    let empty = IntrospectionResponse { .. };
    guard raw_json.len > 0 && raw_json.len <= 4096 else { return empty, false; }
    var reader = json::reader(raw_json);
    var scratch: u8[>..] = [];
    var seen_active = false;
    var had_err = false;
    json::each_member(reader) { key =>
        scratch.clear();
        parse_introspection_field(key, reader, scratch, out, seen_active, had_err);
    };
    guard json::finish(reader) && !had_err && seen_active else {
        return empty, false;
    }
    if !out.active {
        return empty, true;
    }
    return out, true;
}

// ---- RFC 6749 §2.3.1 OAuth 2.0 `client_secret_basic` Credentials ---------

// Encodes `client_id` and `client_secret` into an RFC 6749 §2.3.1 `Authorization: Basic ...` header value
// by applying `application/x-www-form-urlencoded` to each component before joining with `':'` and Base64-encoding.
//
// Example:
//   client_id = "a:b", client_secret = "c d"
//   returns: ok = true, out_header_val = "Basic YSUzQWI6Yytk"
fn encode_oauth2_basic_auth<B>(
    client_id:      const u8[:],
    client_secret:  const u8[:],
    out_header_val: B&,
) -> bool {
    out_header_val.clear();
    guard client_id.len <= 256 && client_secret.len <= 256 else { return false; }
    guard core::index_of_byte(client_id, 0) == -1 && core::index_of_byte(client_secret, 0) == -1 else {
        return false;
    }
    var cred_buf: u8[..1024] = [];
    guard core::append_form_urlencoded(client_id, cred_buf) else { return false; }
    guard cred_buf.len < cred_buf.cap else { return false; }
    cred_buf.push(':');
    guard core::append_form_urlencoded(client_secret, cred_buf) else { return false; }

    var b64_buf: u8[..1536] = [];
    b64_buf.append("Basic ");
    core::base64_encode(cred_buf[..], b64_buf);
    core::secure_zeroize_slice(cred_buf[..]);
    return out_header_val.try_set(b64_buf[..]);
}

// Decodes an RFC 6749 §2.3.1 `Authorization: Basic ...` header value into `out_id` and `out_secret`,
// reversing Base64 and `application/x-www-form-urlencoded` on each component.
//
// Example:
//   header_val = "Basic YSUzQWI6Yytk"
//   returns: ok = true, out_id = "a:b", out_secret = "c d"
fn decode_oauth2_basic_auth(
    header_val: const u8[:],
    out_id:     u8[..256]&,
    out_secret: u8[..256]&,
) -> bool {
    out_id.clear();
    out_secret.clear();
    guard header_val.len > 6 && header_val.len <= 2048 else { return false; }
    guard core::starts_with_fold(header_val, "Basic ") else { return false; }
    let b64_part = core::trim_lws(header_val[6..]);
    guard b64_part.len > 0 else { return false; }

    var raw_cred: u8[..1024] = [];
    guard core::base64_decode(b64_part, raw_cred) else { return false; }
    let colon = core::index_of_byte(raw_cred[..], ':');
    guard colon >= 0 else {
        core::secure_zeroize_slice(raw_cred[..]);
        return false;
    }
    let sec_start = core::add_sat_i64(colon, 1);
    let ok_id = core::decode_form_urlencoded(raw_cred[..colon], out_id);
    let ok_sec = core::decode_form_urlencoded(raw_cred[sec_start..], out_secret);
    core::secure_zeroize_slice(raw_cred[..]);
    guard ok_id && ok_sec else {
        out_id.clear();
        out_secret.clear();
        return false;
    }
    return true;
}
