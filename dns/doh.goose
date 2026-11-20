// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// DNS over HTTPS (DoH, RFC 8484) wire helpers and resolver configuration.
// Supports application/dns-message payload serialization and Base64URL query formatting.
namespace dns;

import std;
import core from "..";
import .wire;
import .internal;

// Configurable DNS-over-HTTPS (DoH RFC 8484) Resolver configuration.
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}

// Formats a DoH POST application/dns-message body for querying `domain` with `qtype`.
// Leaves `out` unchanged on failure.
fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard build_query(domain, qtype, tx_id, out) else { return false; }
    let msg_len = out.len - saved_len;
    guard msg_len >= 12 && msg_len <= dns_internal::DOH_MAX_MESSAGE_OCTETS else { return false; }
    committed = true;
    return true;
}

// Formats base64url query parameter for DoH GET request (RFC 8484 Section 4.1).
// Leaves `out` unchanged on failure.
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out: B&) -> bool {
    // RFC 8484 Section 3: Selection of DoH Server - URI template MUST use https:// scheme
    let base_url, _ = server_url.strip_suffix("{?dns}");
    guard base_url.starts_with_fold("https://") && base_url.len > 8 else { return false; }

    var raw_query: u8[..512] = [];
    // RFC 8484 Section 4.1: The HTTP Request - DNS ID SHOULD be 0 for HTTP cacheability
    guard build_query(domain, qtype, 0, raw_query) else { return false; }

    var encoded_q: u8[..1024] = [];
    core::base64url_encode(raw_query[..], encoded_q);

    let sep: const u8[:] = if !base_url.contains_byte('?') {
        "?dns="
    } else if base_url[base_url.len - 1] == '?' || base_url[base_url.len - 1] == '&' {
        "dns="
    } else {
        "&dns="
    };

    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_append(base_url) else { return false; }
    guard out.try_append(sep) else { return false; }
    guard out.try_append(encoded_q[..]) else { return false; }
    committed = true;
    return true;
}
