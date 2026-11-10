// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8628 OAuth 2.0 Device Authorization Grant response parser and polling backoff state machine.
namespace wing;

import std;
import json;
import core from "..";

struct DeviceAuthResponse {
    device_code:               u8[..128] = [],
    user_code:                 u8[..32]  = [],
    verification_uri:          u8[..256] = [],
    verification_uri_complete: u8[..256] = [],
    expires_in_sec:            i64       = 0,
    interval_sec:              i64       = rfc::DEFAULT_DEVICE_POLL_INTERVAL_SEC,
}

enum DevicePollStatus {
    Granted,
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    TransportError,
}

// Reads a required non-empty JSON string field into `dst`.
//
// Example:
//   reader at "\"WDJB-MJHT\""
//   sets: dst = "WDJB-MJHT", had_err = false
inline fn read_required_oauth_str<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        had_err = true;
        return;
    }
    if !core::read_json_string_into(reader, dst) || dst.len == 0 {
        had_err = true;
    }
}

// Reads an optional nullable JSON string field into `dst`.
//
// Example:
//   reader at "\"https://ex.com?code=1\""
//   sets: dst = "https://ex.com?code=1", had_err = false
inline fn read_nullable_oauth_str<B>(reader: json::Reader&, dst: B&, had_err: bool&) {
    let p = json::peek(reader);
    if p == 'n' {
        json::skip(reader);
    } else if p != '"' || !core::read_json_string_into(reader, dst) {
        had_err = true;
    }
}

// Reads a required positive JSON integer field into `dst`.
//
// Example:
//   reader at "1800"
//   sets: dst = 1800, had_err = false
inline fn read_positive_oauth_int(reader: json::Reader&, dst: i64&, had_err: bool&) {
    let p = json::peek(reader);
    if p >= '0' && p <= '9' {
        dst = json::read_int(reader);
        if dst <= 0 { had_err = true; }
    } else {
        json::skip(reader);
        had_err = true;
    }
}

inline fn is_valid_device_verification_uri(uri: const u8[:]) -> bool {
    let parsed, err = core::parse_url(uri);
    guard err == core::UrlParseError.None && parsed.hostname().len > 0 else { return false; }
    let scheme = parsed.scheme();
    return scheme.eq_ascii_fold("https") || scheme.eq_ascii_fold("http");
}

inline fn mark_device_auth_key_seen(seen_mask: u32&, bit: u32, had_err: bool&) {
    if (seen_mask & bit) != 0 {
        had_err = true;
    }
    seen_mask = seen_mask | bit;
}

// Parses a single field of an RFC 8628 §3.2 Device Authorization Response JSON object.
//
// Example:
//   key = "user_code", reader at "\"WDJB-MJHT\""
//   sets: out.user_code = "WDJB-MJHT", had_err = false
inline fn parse_device_auth_field(
    key:       const u8[:],
    reader:    json::Reader&,
    out:       DeviceAuthResponse&,
    seen_mask: u32&,
    had_err:   bool&,
) {
    if key.contains('\\') {
        had_err = true;
        json::skip(reader);
        return;
    }
    if key == "device_code" {
        mark_device_auth_key_seen(seen_mask, 1, had_err);
        read_required_oauth_str(reader, out.device_code, had_err);
        return;
    }
    if key == "user_code" {
        mark_device_auth_key_seen(seen_mask, 2, had_err);
        read_required_oauth_str(reader, out.user_code, had_err);
        return;
    }
    if key == "verification_uri" || key == "verification_url" {
        mark_device_auth_key_seen(seen_mask, 4, had_err);
        read_required_oauth_str(reader, out.verification_uri, had_err);
        return;
    }
    if key == "verification_uri_complete" {
        mark_device_auth_key_seen(seen_mask, 8, had_err);
        read_nullable_oauth_str(reader, out.verification_uri_complete, had_err);
        return;
    }
    if key == "expires_in" {
        mark_device_auth_key_seen(seen_mask, 16, had_err);
        read_positive_oauth_int(reader, out.expires_in_sec, had_err);
        return;
    }
    if key == "interval" {
        mark_device_auth_key_seen(seen_mask, 32, had_err);
        if json::peek(reader) == 'n' {
            json::skip(reader);
        } else {
            read_positive_oauth_int(reader, out.interval_sec, had_err);
        }
        return;
    }
    json::skip(reader);
}

// Parses an RFC 8628 §3.2 Device Authorization Response JSON document.
// Accepts both standard `"verification_uri"` and legacy `"verification_url"` alias.
//
// Example:
//   raw_json = "{\"device_code\":\"GmRhm\",\"user_code\":\"WDJB\",\"verification_uri\":\"https://ex.com/dev\",\"expires_in\":1800}"
//   returns: out with interval_sec = 5, ok = true
fn parse_device_auth_response(raw_json: const u8[:]) -> DeviceAuthResponse, bool {
    var out = DeviceAuthResponse { .. };
    let empty = DeviceAuthResponse { .. };
    guard raw_json.len > 0 && raw_json.len <= 4096 && raw_json.validate_utf8() else { return empty, false; }
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return empty, false; }
    var seen_mask: u32 = 0;
    var had_err = false;
    json::each_member(reader) { key =>
        parse_device_auth_field(key, reader, out, seen_mask, had_err);
    };
    let complete_uri_ok = out.verification_uri_complete.len == 0 ||
        is_valid_device_verification_uri(out.verification_uri_complete[..]);
    let complete = out.device_code.len > 0 && out.user_code.len > 0 &&
        is_valid_device_verification_uri(out.verification_uri[..]) &&
        complete_uri_ok && out.expires_in_sec > 0;
    guard json::finish(reader) && !had_err && complete else {
        return empty, false;
    }
    return out, true;
}

// Advances the RFC 8628 §3.5 Device Access Token polling interval state machine.
// Returns `(next_interval_sec, should_continue_polling)`.
fn step_device_poll_interval(
    current_interval_sec: i64,
    max_backoff_sec:      i64,
    status:               DevicePollStatus,
) -> i64, bool {
    let base = max(current_interval_sec, rfc::DEFAULT_DEVICE_POLL_INTERVAL_SEC);
    let ceiling = max(max_backoff_sec, base);
    match status {
        Granted => { return 0, false; },
        AuthorizationPending => { return base, true; },
        SlowDown => { return min(core::add_sat_i64(base, rfc::DEVICE_SLOW_DOWN_INCREMENT_SEC), ceiling), true; },
        TransportError => { return min(core::add_sat_i64(base, base), ceiling), true; },
        AccessDenied => { return base, false; },
        ExpiredToken => { return base, false; },
    }
}
