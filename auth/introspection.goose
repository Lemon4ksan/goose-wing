// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OAuth 2.0 Token Introspection (RFC 7662), Token Revocation (RFC 7009), and Basic client auth (RFC 6749).
namespace auth;

import std;
import json;
import core from "..";
import .types;
import .internal;

// RFC 7662 Section 2.1: Introspection Request - encodes token and optional hint as form-urlencoded body.
fn encode_token_endpoint_form<B>(token: const u8[:], hint: TokenTypeHint, out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard token.len > 0 && core::swar_find_ctl(token) == token.len && token.validate_utf8() else {
        return false;
    }
    out.clear();
    guard out.try_append("token=") else { return false; }
    for b in token {
        if b == ' ' {
            guard out.try_push('+' as u8) else { return false; }
        } else if core::is_form_urlencode_safe(b) {
            guard out.try_push(b) else { return false; }
        } else {
            guard out.try_push('%' as u8) else { return false; }
            guard out.try_push(core::UPPER_HEX_DIGITS[((b >> 4) & 0x0F) as i64]) else { return false; }
            guard out.try_push(core::UPPER_HEX_DIGITS[(b & 0x0F) as i64]) else { return false; }
        }
    }
    let hint_suffix = match hint {
        None => "",
        AccessToken => "&token_type_hint=access_token",
        RefreshToken => "&token_type_hint=refresh_token",
    };
    if hint_suffix.len > 0 {
        guard out.try_append(hint_suffix) else { return false; }
    }
    committed = true;
    return true;
}

// RFC 7662 Section 2.2: Introspection Response - parses JSON payload and clears metadata if `active` is false.
//
// Example:
//   raw_json = "{\"active\":true,\"sub\":\"user1\"}"
//   returns: IntrospectionResponse { active: true, sub: "user1", .. }, ok = true
fn parse_introspection_response(raw_json: const u8[:]) -> IntrospectionResponse, bool {
    var resp = IntrospectionResponse { .. };
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return IntrospectionResponse { .. }, false; }

    var seen_mask: u32                                = 0;
    var seen_ext:  auth_internal::SeenHeaderKey[..32] = [];
    var had_err = false;
    json::each_member(reader) { key =>
        auth_internal::parse_introspection_field(key, reader, resp, seen_mask, seen_ext, had_err);
    };

    guard json::finish(reader) && !had_err && (seen_mask & 1) != 0 else {
        return IntrospectionResponse { .. }, false;
    }
    if !resp.active {
        return IntrospectionResponse { .. }, true;
    }
    return resp, true;
}

// RFC 6749 Section 2.3.1: Client Password - encodes "Basic base64(urlencode(id):urlencode(secret))" into `out`.
fn encode_oauth2_basic_auth<B>(
    client_id:     const u8[:],
    client_secret: const u8[:],
    out:           B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard client_id.len > 0 else { return false; }
    guard auth_internal::is_valid_basic_auth_credential(client_id) else { return false; }
    guard auth_internal::is_valid_basic_auth_credential(client_secret) else { return false; }

    var combined: u8[..1024] = [];
    defer core::secure_zeroize_slice(combined[..]);
    guard core::append_form_urlencoded(client_id, combined) else { return false; }
    guard combined.try_push(':' as u8) else { return false; }
    guard core::append_form_urlencoded(client_secret, combined) else { return false; }

    var b64: u8[..1400] = [];
    defer core::secure_zeroize_slice(b64[..]);
    core::base64_encode(combined[..], b64);

    out.clear();
    guard out.try_append("Basic ") && out.try_append(b64[..]) else { return false; }
    committed = true;
    return true;
}

// RFC 6749 Section 2.3.1: Client Password - decodes an HTTP Basic Authorization header value.
//
// Example:
//   header_val = "Basic Y2lkOnNlYw=="
//   returns: true, out_id = "cid", out_secret = "sec"
fn decode_oauth2_basic_auth<B1, B2>(
    header_val: const u8[:],
    out_id:     B1&,
    out_secret: B2&,
) -> bool {
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out_secret[..]);
        out_id.resize(0);
        out_secret.resize(0);
    };
    let raw_b64, has_basic = header_val.trim_lws().strip_prefix_fold("basic ");
    guard has_basic else { return false; }
    let b64 = raw_b64.trim_lws();
    guard b64.len > 0 else { return false; }

    var decoded: u8[..1024] = [];
    defer core::secure_zeroize_slice(decoded[..]);
    guard core::base64_decode(b64, decoded) else { return false; }

    let enc_id, enc_secret, has_colon = decoded[..].split_once_byte(':');
    guard has_colon else { return false; }

    var id_buf:  u8[..256] = [];
    var sec_buf: u8[..256] = [];
    defer core::secure_zeroize_slice(sec_buf[..]);
    guard core::decode_form_urlencoded(enc_id, id_buf) else { return false; }
    guard core::decode_form_urlencoded(enc_secret, sec_buf) else { return false; }
    guard id_buf.len > 0 else { return false; }
    guard auth_internal::is_valid_basic_auth_credential(id_buf[..]) else { return false; }
    guard auth_internal::is_valid_basic_auth_credential(sec_buf[..]) else { return false; }

    guard out_id.try_set(id_buf[..]) && out_secret.try_set(sec_buf[..]) else { return false; }
    committed = true;
    return true;
}
