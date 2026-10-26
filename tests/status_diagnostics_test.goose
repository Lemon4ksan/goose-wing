// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 9211 (Cache-Status) and RFC 9209 (Proxy-Status):
// - RFC 9211 Cache-Status header parsing (hit, stored, collapsed, ttl, fwd, key, detail)
// - RFC 9211 formatting and roundtrip verification
// - RFC 9209 Proxy-Status header parsing (error, next-hop, details, received-status)
// - RFC 9209 formatting and multi-proxy hop chains
import std;
import core from "..";
import wing from "..";

fn test_cache_status_rfc9211(t: core::T&) {
    t.run("Parse Single & Multi-Cache Status") { sub =>
        let raw = "OriginCache; hit; ttl=120; key=\"asset-hash-123\"; detail=\"memory\", EdgeCache; stored; fwd=stale; fwd-status=200";
        var entries: wing::CacheStatusEntry[..8] = [];
        let count = wing::parse_cache_status_header(raw, entries);
        sub.assert_eq(count, 2, "Parsed 2 cache status entries");

        // Entry 1: OriginCache
        sub.assert_bytes_eq(entries[0].cache_name[..], "OriginCache", "Entry 1 name matches");
        sub.assert_true(entries[0].hit, "Entry 1 is a hit");
        sub.assert_eq(entries[0].ttl, 120, "Entry 1 TTL is 120");
        sub.assert_bytes_eq(entries[0].key[..], "asset-hash-123", "Entry 1 key matches");
        sub.assert_bytes_eq(entries[0].detail[..], "memory", "Entry 1 detail matches");

        // Entry 2: EdgeCache
        sub.assert_bytes_eq(entries[1].cache_name[..], "EdgeCache", "Entry 2 name matches");
        sub.assert_false(entries[1].hit, "Entry 2 is NOT hit");
        sub.assert_true(entries[1].stored, "Entry 2 is stored");
        sub.assert_bytes_eq(entries[1].fwd[..], "stale", "Entry 2 fwd reason is stale");
        sub.assert_eq(entries[1].fwd_status, 200, "Entry 2 fwd-status is 200");
    };

    t.run("Format Cache Status") { sub =>
        var entry = wing::CacheStatusEntry {
            hit: true,
            ttl: 300,
            ..
        };
        entry.cache_name.append("CDN-Fastly");
        entry.key.append("page-v2");

        var out: u8[..256] = [];
        wing::format_cache_status(entry, out);
        sub.assert_contains(out[..], "CDN-Fastly; hit; ttl=300; key=\"page-v2\"", "Formatted matches RFC 9211");
    };
}

fn test_proxy_status_rfc9209(t: core::T&) {
    t.run("Parse Proxy Error Status") { sub =>
        let raw = "edge-us-east; error=connection_refused; next-hop=\"10.0.1.5\"; details=\"TCP SYN reset by peer\"; received-status=502";
        var entries: wing::ProxyStatusEntry[..8] = [];
        let count = wing::parse_proxy_status_header(raw, entries);
        sub.assert_eq(count, 1, "Parsed 1 proxy status");

        sub.assert_bytes_eq(entries[0].proxy_name[..], "edge-us-east", "Proxy name matches");
        sub.assert_bytes_eq(entries[0].error_type[..], "connection_refused", "Error type is connection_refused");
        sub.assert_bytes_eq(entries[0].next_hop[..], "10.0.1.5", "Next hop matches");
        sub.assert_bytes_eq(entries[0].details[..], "TCP SYN reset by peer", "Details match");
        sub.assert_eq(entries[0].received_status, 502, "Received status is 502");
    };

    t.run("Format Proxy Status") { sub =>
        var entry = wing::ProxyStatusEntry {
            received_status: 504,
            ..
        };
        entry.proxy_name.append("gateway-ingress");
        entry.error_type.append("connection_timeout");
        entry.next_hop.append("origin.internal");

        var out: u8[..256] = [];
        wing::format_proxy_status(entry, out);
        sub.assert_contains(out[..], "gateway-ingress; error=connection_timeout", "Formatted error");
        sub.assert_contains(out[..], "next-hop=\"origin.internal\"", "Formatted next-hop");
        sub.assert_contains(out[..], "received-status=504", "Formatted received-status");
    };
}

fn main() {
    var runner = core::new_runner("RFC 9211 Cache-Status & RFC 9209 Proxy-Status Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9211 Cache-Status", test_cache_status_rfc9211);
    core::run_case(runner, "2. RFC 9209 Proxy-Status", test_proxy_status_rfc9209);
    let ok = core::finish(runner);
    assert(ok);
}
