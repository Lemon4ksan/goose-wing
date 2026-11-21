// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OAuth 2.0 Device Authorization Grant helpers (RFC 8628).
namespace auth;

import std;
import json;
import core;
import rfc.http;
import .types;
import .internal;

// RFC 8628 Section 3.2: Device Authorization Response - parses response JSON fields.
//
// Example:
//   raw_json = "{\"device_code\":\"dc1\",\"user_code\":\"uc1\",\"verification_uri\":\"https://ex.com\",\"expires_in\":600}"
//   returns: DeviceAuthResponse { device_code: "dc1", ... }, ok = true
fn parse_device_auth_response(raw_json: const u8[:]) -> DeviceAuthResponse, bool {
    var resp = DeviceAuthResponse { .. };
    var reader = json::reader(raw_json);
    guard json::peek(reader) == '{' else { return DeviceAuthResponse { .. }, false; }

    var seen_mask: u32 = 0;
    var had_err = false;
    json::each_member(reader) { key =>
        auth_internal::parse_device_auth_field(key, reader, resp, seen_mask, had_err);
    };

    guard json::finish(reader) && !had_err && (seen_mask & 23) == 23 else {
        return DeviceAuthResponse { .. }, false;
    }
    guard auth_internal::is_valid_device_verification_uri(resp.verification_uri[..]) else {
        return DeviceAuthResponse { .. }, false;
    }
    if resp.verification_uri_complete.len > 0 {
        guard auth_internal::is_valid_device_verification_uri(resp.verification_uri_complete[..]) else {
            return DeviceAuthResponse { .. }, false;
        }
    }
    return resp, true;
}

// RFC 8628 Section 3.5: Device Access Token Response - steps polling backoff by status.
fn step_device_poll_interval(
    status:               DevicePollStatus,
    current_interval_sec: i64,
    max_backoff_sec:      i64,
) -> i64, bool {
    let base = max(current_interval_sec, rfc::DEFAULT_DEVICE_POLL_INTERVAL_SEC);
    let ceiling = max(max_backoff_sec, rfc::DEFAULT_DEVICE_POLL_INTERVAL_SEC);
    match status {
        AuthorizationPending => { return min(base, ceiling), true; },
        SlowDown => { return min(core::add_sat_i64(base, rfc::DEVICE_SLOW_DOWN_INCREMENT_SEC), ceiling), true; },
        TransportError => { return min(core::add_sat_i64(base, base), ceiling), true; },
        Granted => { return current_interval_sec, false; },
        AccessDenied => { return current_interval_sec, false; },
        ExpiredToken => { return current_interval_sec, false; },
    }
}
