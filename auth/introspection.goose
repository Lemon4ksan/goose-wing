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
    guard token.len > 0 && token.len <= 4096 else { return false; }
    var buf:   u8[..8192] = [];
    var chunk: u8[..1024] = [];
    buf.append("token=");
    var off: i64 = 0;
    while off < token.len {
        let end = min(core::add_sat_i64(off, 256), token.len);
        chunk.clear();
        guard core::append_form_urlencoded(token[off..end], chunk) && buf.try_append(chunk[..]) else {
            return false;
        }
        off = end;
    }
    if hint == TokenTypeHint.AccessToken {
        guard buf.try_append("&token_type_hint=access_token") else { return false; }
    } else if hint == TokenTypeHint.RefreshToken {
        guard buf.try_append("&token_type_hint=refresh_token") else { return false; }
    }
    return out.try_set(buf[..]);
}

// Parses `"aud"` field (single string or array of strings) in an RFC 7662 introspection response.
//
// Example:
//   reader at "\"https://resource.example.org\""
//   returns: ok = true, out.aud[0] = "https://resource.example.org"
inline fn parse_introspection_aud(reader: json::Reader&, out: IntrospectionResponse&) -> bool {
    let p = json::peek(reader);
    if p == '"' {
        var item: u8[..128] = [];
        return core::read_json_string_into(reader, item) && item.len > 0 && out.aud.try_push(item);
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
            var item: u8[..128] = [];
            if !core::read_json_string_into(reader, item) || item.len == 0 || !out.aud.try_push(item) {
                ok = false;
            }
        }
    };
    guard ok && out.aud.len > 0 else {
        out.aud.clear();
        return false;
    }
    return true;
}

inline fn mark_introspection_key_seen(seen_mask: u32&, bit: u32, had_err: bool&) {
    if (seen_mask & bit) != 0 {
        had_err = true;
    }
    seen_mask = seen_mask | bit;
}

// Reads a JSON string member into `dst` for RFC 7662 introspection metadata.
//
// Example:
//   reader at "\"read write\""
//   sets: dst = "read write", had_err = false
inline fn parse_introspection_str_field<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
    } else if !core::read_json_string_into(reader, dst) {
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
inline fn read_unique_introspection_str<B>(
    reader:    json::Reader&,
    dst:       B&,
    seen_mask: u32&,
    bit:       u32,
    had_err:   bool&,
) -> bool {
    mark_introspection_key_seen(seen_mask, bit, had_err);
    parse_introspection_str_field(reader, dst, had_err);
    return true;
}

inline fn read_unique_introspection_int(
    reader:    json::Reader&,
    dst:       i64&,
    seen_mask: u32&,
    bit:       u32,
    had_err:   bool&,
) {
    mark_introspection_key_seen(seen_mask, bit, had_err);
    parse_introspection_int_field(reader, dst, had_err);
}

// Parses string metadata fields of an RFC 7662 Token Introspection Response JSON object.
//
// Example:
//   key = "client_id", reader at "\"l23\""
//   sets: out.client_id = "l23", returns: true
inline fn parse_introspection_str_member(
    key:       const u8[:],
    reader:    json::Reader&,
    out:       IntrospectionResponse&,
    seen_mask: u32&,
    had_err:   bool&,
) -> bool {
    if key == "scope" { return read_unique_introspection_str(reader, out.scope, seen_mask, 2, had_err); }
    if key == "client_id" { return read_unique_introspection_str(reader, out.client_id, seen_mask, 4, had_err); }
    if key == "username" { return read_unique_introspection_str(reader, out.username, seen_mask, 8, had_err); }
    if key == "token_type" { return read_unique_introspection_str(reader, out.token_type, seen_mask, 16, had_err); }
    if key == "sub" { return read_unique_introspection_str(reader, out.sub, seen_mask, 32, had_err); }
    if key == "iss" { return read_unique_introspection_str(reader, out.iss, seen_mask, 64, had_err); }
    if key == "jti" { return read_unique_introspection_str(reader, out.jti, seen_mask, 128, had_err); }
    return false;
}

// Parses a single field of an RFC 7662 §2.2 Token Introspection Response JSON object.
//
// Example:
//   key = "active", reader at "true"
//   sets: out.active = true, seen_mask |= 1
inline fn parse_introspection_field(
    key:       const u8[:],
    reader:    json::Reader&,
    out:       IntrospectionResponse&,
    seen_mask: u32&,
    had_err:   bool&,
) {
    if key.contains('\\') {
        json::skip(reader);
        had_err = true;
        return;
    }
    if key == "active" {
        let p = json::peek(reader);
        if (seen_mask & 1) != 0 || (p != 't' && p != 'f') {
            json::skip(reader);
            had_err = true;
        } else {
            out.active = json::read_bool(reader);
            seen_mask = seen_mask | 1;
        }
        return;
    }
    if parse_introspection_str_member(key, reader, out, seen_mask, had_err) { return; }
    if key == "aud" {
        mark_introspection_key_seen(seen_mask, 256, had_err);
        if !parse_introspection_aud(reader, out) { had_err = true; }
        return;
    }
    if key == "exp" { read_unique_introspection_int(reader, out.exp, seen_mask, 512, had_err); return; }
    if key == "iat" { read_unique_introspection_int(reader, out.iat, seen_mask, 1024, had_err); return; }
    if key == "nbf" { read_unique_introspection_int(reader, out.nbf, seen_mask, 2048, had_err); return; }
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
    guard raw_json.len > 0 && raw_json.len <= 4096 && raw_json.validate_utf8() else { return empty, false; }
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return empty, false; }
    var seen_mask: u32 = 0;
    var had_err = false;
    json::each_member(reader) { key =>
        parse_introspection_field(key, reader, out, seen_mask, had_err);
    };
    guard json::finish(reader) && !had_err && (seen_mask & 1) != 0 else {
        return empty, false;
    }
    if !out.active {
        return empty, true;
    }
    return out, true;
}

// ---- RFC 6749 §2.3.1 OAuth 2.0 `client_secret_basic` Credentials ---------

// RFC 7617 Section 2: User-id and password MUST NOT contain ASCII control characters (0x00..0x1F, 0x7F) and MUST be valid UTF-8.
inline fn is_valid_basic_auth_credential(s: const u8[:]) -> bool {
    return core::swar_find_ctl(s) == s.len && s.validate_utf8();
}

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
    guard is_valid_basic_auth_credential(client_id) && is_valid_basic_auth_credential(client_secret) else {
        return false;
    }
    var cred_buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(cred_buf[..]);
    guard core::append_form_urlencoded(client_id, cred_buf) else { return false; }
    guard cred_buf.try_push(':') else { return false; }
    guard core::append_form_urlencoded(client_secret, cred_buf) else { return false; }

    var b64_buf: u8[..1536] = [];
    b64_buf.append("Basic ");
    core::base64_encode(cred_buf[..], b64_buf);
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
    guard header_val.starts_with_fold("Basic ") else { return false; }
    let b64_part = header_val[6..].trim_lws();
    guard b64_part.len > 0 else { return false; }

    var raw_cred: u8[..1024] = [];
    defer core::secure_zeroize_slice(raw_cred[..]);
    guard core::base64_decode(b64_part, raw_cred) else { return false; }
    let id_part, sec_part, has_colon = raw_cred[..].split_once_byte(':');
    guard has_colon else { return false; }
    let ok_id = core::decode_form_urlencoded(id_part, out_id);
    let ok_sec = core::decode_form_urlencoded(sec_part, out_secret);
    let ok_ctl = is_valid_basic_auth_credential(out_id[..]) && is_valid_basic_auth_credential(out_secret[..]);
    guard ok_id && ok_sec && ok_ctl else {
        out_id.clear();
        out_secret.clear();
        return false;
    }
    return true;
}
