// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// DNS over HTTPS (DoH, RFC 8484) wire helpers and resolver configuration.
// Supports application/dns-message payload serialization and Base64URL query formatting.
namespace wing;

import std;
import core from "..";
import .wire;

// ---- DNS over HTTPS (DoH RFC 8484) Wire Helpers --------------------------

// Formats a DoH POST application/dns-message body for querying `domain` with `qtype`.
fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out_body: B&) -> bool {
    return build_dns_query(domain, qtype, tx_id, out_body);
}

// Formats base64url query parameter for DoH GET request (RFC 8484 Section 4.1).
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out_url: B&) -> bool {
    var raw_query: u8[..512] = [];
    guard build_dns_query(domain, qtype, 0, raw_query) else { return false; }

    var encoded_q: u8[..1024] = [];
    core::base64url_encode(raw_query[..], encoded_q);

    let sep: const u8[:] = if !server_url.contains_byte('?') {
        "?dns="
    } else if server_url[server_url.len - 1] == '?' || server_url[server_url.len - 1] == '&' {
        "dns="
    } else {
        "&dns="
    };

    guard out_url.len + server_url.len + sep.len + encoded_q.len <= out_url.cap else { return false; }

    out_url.append(server_url);
    out_url.append(sep);
    out_url.append(encoded_q[..]);
    return true;
}

// Configurable DNS-over-HTTPS (DoH RFC 8484) Resolver configuration.
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}
