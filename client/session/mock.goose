// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Mock exchange definitions and response synthesis for client simulation.
namespace wing;

import std;
import client.redirect;
import client.response;
import http.headers;
import client.session.ssrf;

// ---- mock exchange model ---------------------------------------------------

struct MockExchange {
    pattern_url: u8[..256] = [],
    method: u8[..16] = [],
    status_code: i32 = 200,
    headers: HeaderItem[..8] = [],
    set_cookies: u8[..128][..4] = [],
    resolved_ips: u8[..64][..4] = [],
    body: u8[..1024] = [],
    protocol: u8[..16] = [],
    simulate_quic_blocked: bool = false,
}

fn add_mock_set_cookie(route: MockExchange&, set_cookie_raw: const u8[:]) {
    if route.set_cookies.len < 8 {
        var cookie_buf: u8[..256] = [];
        cookie_buf.append(set_cookie_raw);
        route.set_cookies.push(cookie_buf);
    }
}

fn add_mock_header(route: MockExchange&, name: const u8[:], value: const u8[:]) {
    if route.headers.len < 16 {
        route.headers.push(make_header(name, value));
    }
}

fn add_mock_resolved_ip(route: MockExchange&, ip_str: const u8[:]) {
    if route.resolved_ips.len < 4 {
        var ip_buf: u8[..64] = [];
        ip_buf.append(ip_str);
        route.resolved_ips.push(ip_buf);
    }
}

fn set_mock_quic_blocked(route: MockExchange&, blocked: bool = true) {
    route.simulate_quic_blocked = blocked;
}

fn set_mock_protocol(route: MockExchange&, proto: const u8[:]) {
    route.protocol.clear();
    route.protocol.append(proto);
}

// Validates resolved mock IPs against SSRF guard policy.
fn validate_mock_route_dns(route: const MockExchange&, guard_config: const SsrfGuardPolicy&) -> RedirectError {
    if route.resolved_ips.len == 0 {
        return RedirectError.None;
    }
    var ips_slice: const u8[:][4] = ["", "", "", ""];
    for idx in route.resolved_ips.len {
        ips_slice[idx] = route.resolved_ips[idx][..];
    }
    return validate_resolved_ips_against_ssrf(ips_slice[..route.resolved_ips.len], guard_config);
}

// Extracts origin string "host:port" from parsed Url.
fn format_url_origin<B>(url_val: const core::Url&, out: B&) {
    let host = core::hostname(url_val);
    let port = core::effective_port(url_val);
    out.append(host);
    out.push(':');
    format(out, port);
}

fn target_has_scheme(target: const u8[:]) -> bool {
    if target.len < 8 { return false; }
    for i in target.len - 2 {
        if target[i] == ':' && target[i + 1] == '/' && target[i + 2] == '/' {
            return true;
        }
    }
    return false;
}

fn resolve_target_origin<B>(target: const u8[:], out: B&) {
    if target_has_scheme(target) {
        let parsed, err = core::parse_url(target);
        if parsed.valid {
            format_url_origin(parsed, out);
            return;
        }
    }
    out.append(target);
}

// Synthesizes an HTTP Response from a matched MockExchange.
fn build_mock_response(
    route: const MockExchange&,
    current_url: const core::Url&,
    sent_headers: const HeaderItem[:]
) -> Response {
    var resp = Response {
        status_code: route.status_code,
        effective_url: copy(current_url.href),
        ..
    };
    if route.protocol.len > 0 {
        resp.protocol.clear();
        resp.protocol.append(route.protocol[..]);
    }
    for &h in route.headers {
        resp.headers.push(copy(h));
    }
    for &sc in route.set_cookies {
        resp.set_cookies.push(copy(sc));
    }
    resp.body.append(route.body[..]);
    for &sent_h in sent_headers {
        resp.sent_headers.push(copy(sent_h));
    }
    return resp;
}
