// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Mock exchange definitions for deterministic offline client simulation.
namespace client;

import std;
import core;
import rfc.http;
import http.headers;

// ---- mock exchange model ---------------------------------------------------

struct MockExchange {
    pattern_url:           u8[..256]       = [],
    method:                u8[..16]        = [],
    status_code:           i32             = rfc::STATUS_OK,
    headers:               http::HeaderMap = http::HeaderMap { .. },
    resolved_ips:          u8[..64][..4]   = [],
    body:                  u8[..1024]      = [],
    protocol:              u8[..16]        = [],
    simulate_quic_blocked: bool            = false,
}

fn add_mock_set_cookie(route: MockExchange&, cookie_str: const u8[:]) {
    let _ = http::append_header(route.headers, "Set-Cookie", cookie_str);
}

fn add_mock_header(route: MockExchange&, name: const u8[:], value: const u8[:]) {
    let _ = http::append_header(route.headers, name, value);
}

fn add_mock_resolved_ip(route: MockExchange&, ip_str: const u8[:]) {
    var ip_buf: u8[..64] = [];
    guard ip_buf.try_set(ip_str) else { return; }
    let _ = route.resolved_ips.try_push(ip_buf);
}

fn set_mock_quic_blocked(route: MockExchange&, blocked: bool = true) {
    route.simulate_quic_blocked = blocked;
}
