// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 10036: Incremental Forwarding of HTTP Messages.
// Defines the "Incremental" HTTP header field which instructs intermediaries
// to forward messages incrementally rather than buffering the entire message.
namespace wing;

import std;
import core from "..";
import .headers;
import client.response;

// ---- RFC 10036 Constants --------------------------------------------------

const HEADER_INCREMENTAL: const u8[:] = "Incremental";

// Proxy-Status error parameter values (RFC 10036 Section 3)
const PROXY_ERROR_INCREMENTAL_REFUSED:      const u8[:] = "incremental_refused";
const PROXY_ERROR_CONNECTION_LIMIT_REACHED: const u8[:] = "connection_limit_reached";

// ---- Header Parsing & Serialization ---------------------------------------

// Parses an RFC 10036 Incremental header field value.
// Per RFC 10036 Section 2:
// - Must be an RFC 9651 Structured Fields Item with Boolean type (?1 or ?0).
// - Recipients MUST ignore the field if it contains any type other than a Boolean.
// Returns (is_incremental, is_valid_boolean).
//
// Example:
//   val = "?1"
//   returns: true, ok = true
fn parse_incremental_header(val: const u8[:]) -> bool, bool {
    let s = val.trim_lws();
    guard s.len >= 2 && s[0] == '?' else { return false, false; }
    let b = s[1];
    guard b == '1' || b == '0' else { return false, false; }

    // If parameters exist after semicolon, ignore them per RFC 10036 Section 2
    if s.len > 2 {
        let next_ch = s[2];
        guard next_ch == ';' || next_ch == ' ' || next_ch == '\t' else { return false, false; }
    }

    return b == '1', true;
}

// Inspects a HeaderMap to determine whether incremental forwarding was requested.
fn is_incremental_requested(headers: const HeaderMap&) -> bool {
    let val = get_header(headers, HEADER_INCREMENTAL);
    guard val.len > 0 else { return false; }
    let is_inc, ok = parse_incremental_header(val);
    return ok && is_inc;
}

// Appends `Incremental: ?1` or `Incremental: ?0` to outgoing headers.
fn append_incremental_header(out_headers: HeaderMap&, incremental: bool) -> bool {
    return append_header(out_headers, HEADER_INCREMENTAL, if incremental { "?1" } else { "?0" });
}

// ---- Intermediary Error Handling (RFC 10036 Section 3) --------------------

// Formats a 501 Not Implemented response with `incremental_refused` Proxy-Status
// when an intermediary cannot forward incrementally due to policy/security constraints.
// Formats `Proxy-Status` header value with `incremental_refused` (RFC 10036 Section 3).
fn format_incremental_refused_proxy_status<B>(out: B&, proxy_name: const u8[:]) {
    out.append(proxy_name);
    out.append("; error=");
    out.append(PROXY_ERROR_INCREMENTAL_REFUSED);
}

// Formats `Proxy-Status` header value with `connection_limit_reached` (RFC 10036 Section 3).
fn format_incremental_limit_reached_proxy_status<B>(out: B&, proxy_name: const u8[:]) {
    out.append(proxy_name);
    out.append("; error=");
    out.append(PROXY_ERROR_CONNECTION_LIMIT_REACHED);
}
