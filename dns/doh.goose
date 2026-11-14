// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// DNS over HTTPS (DoH, RFC 8484) wire helpers and resolver configuration.
// Supports application/dns-message payload serialization and Base64URL query formatting.
namespace wing;

import std;
import core from "..";
import .wire;

// ---- DNS over HTTPS (DoH RFC 8484) Wire Helpers --------------------------

// RFC 8484 Section 6: Definition of the "application/dns-message" Media Type - 65535-octet ceiling
const DOH_MAX_MESSAGE_OCTETS: i64 = 65535;

// Formats a DoH POST application/dns-message body for querying `domain` with `qtype`.
fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out_body: B&) -> bool {
    let saved_len = out_body.len;
    var committed = false;
    defer if !committed { out_body.resize(saved_len); };
    guard build_dns_query(domain, qtype, tx_id, out_body) else { return false; }
    let msg_len = out_body.len - saved_len;
    guard msg_len >= 12 && msg_len <= DOH_MAX_MESSAGE_OCTETS else { return false; }
    committed = true;
    return true;
}

// Formats base64url query parameter for DoH GET request (RFC 8484 Section 4.1).
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out_url: B&) -> bool {
    // RFC 8484 Section 3: Selection of DoH Server - URI template MUST use https:// scheme
    let stripped_tmpl, _ = server_url.strip_suffix("{?dns}");
    let base_url = if stripped_tmpl.len > 0 { stripped_tmpl } else { server_url };
    guard base_url.starts_with_fold("https://") && base_url.len > 8 else { return false; }

    var raw_query: u8[..512] = [];
    // RFC 8484 Section 4.1: The HTTP Request - DNS ID SHOULD be 0 for HTTP cacheability
    guard build_dns_query(domain, qtype, 0, raw_query) else { return false; }

    var encoded_q: u8[..1024] = [];
    core::base64url_encode(raw_query[..], encoded_q);

    let sep: const u8[:] = if !base_url.contains_byte('?') {
        "?dns="
    } else if base_url[base_url.len - 1] == '?' || base_url[base_url.len - 1] == '&' {
        "dns="
    } else {
        "&dns="
    };

    let saved_len = out_url.len;
    var committed = false;
    defer if !committed { out_url.resize(saved_len); };
    guard out_url.try_append(base_url) else { return false; }
    guard out_url.try_append(sep) else { return false; }
    guard out_url.try_append(encoded_q[..]) else { return false; }
    committed = true;
    return true;
}

// Configurable DNS-over-HTTPS (DoH RFC 8484) Resolver configuration.
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}
