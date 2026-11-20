// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client-session URL and resolved-IP SSRF enforcement returning RedirectError.
namespace wing;

import std;
import core from "../..";
import client.redirect;
import security.ssrf;

fn validate_url_against_ssrf(url_val: const core::Url&, policy: const security::SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled else { return RedirectError.None; }

    if policy.https_only && url_val.scheme() != "https" {
        return RedirectError.SchemeDowngradeBlocked;
    }

    let raw_port = url_val.port;
    let port_val = if raw_port == 0 { 0 } else { url_val.effective_port() };
    if policy.denied_ports.contains(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }
    if policy.allowed_ports.len > 0 {
        if !policy.allowed_ports.contains(port_val) {
            return RedirectError.SsrfBlockedUrl;
        }
    } else if policy.deny_local_network && security::is_dangerous_service_port(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }

    let host_str = url_val.hostname();
    if security::is_cloud_metadata_domain(host_str) {
        return RedirectError.SsrfBlockedIp;
    }
    if policy.deny_local_network {
        if security::is_forbidden_internal_host(host_str) {
            return RedirectError.SsrfBlockedIp;
        }
    } else if security::is_cloud_metadata_or_reserved_ip(host_str) || security::is_non_canonical_ipv4(host_str) {
        return RedirectError.SsrfBlockedIp;
    }

    return RedirectError.None;
}

fn validate_resolved_ips_against_ssrf(ips: const u8[:][:], policy: const security::SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled else { return RedirectError.None; }
    guard ips.len > 0 else { return RedirectError.SsrfBlockedIp; }
    for ip in ips {
        guard security::is_valid_resolved_ip_literal(ip) else {
            return RedirectError.SsrfBlockedIp;
        }
        let blocked = if policy.deny_local_network {
            security::is_private_or_reserved_ip(ip)
        } else {
            security::is_cloud_metadata_or_reserved_ip(ip)
        };
        if blocked {
            return RedirectError.SsrfBlockedIp;
        }
    }
    return RedirectError.None;
}
