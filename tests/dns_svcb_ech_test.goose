// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/dns_svcb_ech_test.goose
// Verification Suite for RFC 9460 (HTTPS/SVCB DNS Resource Records),
// Encrypted Client Hello (ECH) parameter extraction, and DNS Cache Lifecycle.
import std;
import core from "..";
import wing from "..";

fn test_rfc9460_svcb_https_rdata(t: core::T&) {
    t.run("1. Multi-ALPN, Port, and Dual-Stack IP Hints") { sub =>
        // Parameter wire block:
        // Key 1 (ALPN, len 6): "h3" (len 2) + "h2" (len 2) -> 02 68 33 02 68 32
        // Key 2 (NoDefaultAlpn, len 0)
        // Key 3 (Port, len 2): 8443 (0x20FB)
        // Key 4 (IPv4Hint, len 8): 192.0.2.1 (0xC0000201), 198.51.100.1 (0xC6336401)
        // Key 5 (ECH, len 10): 01 02 03 04 05 06 07 08 09 0A
        // Key 6 (IPv6Hint, len 16): 2001:0db8::1
        var raw_params: u8[>..] = [];
        // Key 1
        raw_params.append([0x00, 0x01, 0x00, 0x06, 0x02, 'h', '3', 0x02, 'h', '2']);
        // Key 2
        raw_params.append([0x00, 0x02, 0x00, 0x00]);
        // Key 3
        raw_params.append([0x00, 0x03, 0x00, 0x02, 0x20, 0xFB]);
        // Key 4
        raw_params.append([0x00, 0x04, 0x00, 0x08, 0xC0, 0x00, 0x02, 0x01, 0xC6, 0x33, 0x64, 0x01]);
        // Key 5
        raw_params.append([0x00, 0x05, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        // Key 6
        raw_params.append([
            0x00, 0x06, 0x00, 0x10,
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);

        var rec = wing::HttpsRecord { .. };
        let ok = wing::parse_https_svc_params(raw_params[..], rec);
        sub.assert_true(ok, "parse_https_svc_params succeeds on well-formed ascending keys");

        sub.assert_eq(rec.alpns.len, 2, "Parsed 2 ALPN protocols");
        sub.assert_bytes_eq(rec.alpns[0], "h3", "First ALPN is h3");
        sub.assert_bytes_eq(rec.alpns[1], "h2", "Second ALPN is h2");

        sub.assert_true(rec.no_default_alpn, "no_default_alpn flag parsed");
        sub.assert_eq(rec.port, 8443, "Custom port parsed");

        sub.assert_eq(rec.ipv4_hints.len, 2, "Parsed 2 IPv4 hints");
        sub.assert_eq(rec.ipv4_hints[0], 0xC0000201, "First IPv4 hint matches 192.0.2.1");
        sub.assert_eq(rec.ipv4_hints[1], 0xC6336401, "Second IPv4 hint matches 198.51.100.1");

        sub.assert_true(rec.has_ech, "ECH flag set");
        sub.assert_eq(rec.ech_config_list.len, 10, "ECHConfigList length is 10 bytes");
        sub.assert_eq(rec.ech_config_list[0], 1, "First byte of ECHConfigList matches");

        sub.assert_eq(rec.ipv6_hints.len, 1, "Parsed 1 IPv6 hint");
        sub.assert_eq(rec.ipv6_hints[0][0], 0x20, "First byte of IPv6 hint is 0x20");
        sub.assert_eq(rec.ipv6_hints[0][15], 0x01, "Last byte of IPv6 hint is 0x01");
    };

    t.run("2. RFC 9460 Invariant Rejections (Order & Bounds)") { sub =>
        // Reject out-of-order keys: Key 4 followed by Key 3
        var out_of_order: u8[>..] = [];
        out_of_order.append([0x00, 0x04, 0x00, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        out_of_order.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        var r1 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(out_of_order[..], r1), "Out-of-order keys rejected");

        // Reject duplicate keys: Key 3 twice
        var duplicate_key: u8[>..] = [];
        duplicate_key.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        duplicate_key.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        var r2 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(duplicate_key[..], r2), "Duplicate keys rejected");

        // Reject bad port length: 1 byte
        var bad_port: u8[>..] = [];
        bad_port.append([0x00, 0x03, 0x00, 0x01, 0x50]);
        var r3 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(bad_port[..], r3), "Port length != 2 rejected");

        // Reject bad IPv4 length: 6 bytes (not multiple of 4)
        var bad_ip4: u8[>..] = [];
        bad_ip4.append([0x00, 0x04, 0x00, 0x06, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x01]);
        var r4 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(bad_ip4[..], r4), "IPv4 hint length not multiple of 4 rejected");

        // Reject truncated parameter value (stated length 4, actual bytes 2)
        var trunc_val: u8[>..] = [];
        trunc_val.append([0x00, 0x04, 0x00, 0x04, 0xC0, 0x00]);
        var r5 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(trunc_val[..], r5), "Truncated parameter value rejected");
    };
}

fn test_doh_query_generation(t: core::T&) {
    t.run("1. DoH POST Body and GET URL Construction") { sub =>
        var post_body: u8[>..] = [];
        let ok_post = wing::build_doh_post_body("cloudflare.com", wing::DNS_QTYPE_HTTPS, 0x1234, post_body);
        sub.assert_true(ok_post, "build_doh_post_body succeeds");
        sub.assert_true(post_body.len >= 12, "Post body at least DNS header size (12 bytes)");

        // Header check: tx_id 0x1234
        sub.assert_eq(post_body[0], 0x12, "Tx ID byte 0");
        sub.assert_eq(post_body[1], 0x34, "Tx ID byte 1");

        // GET URL with base64url query parameter
        var get_url: u8[>..] = [];
        let ok_get = wing::build_doh_get_url("https://1.1.1.1/dns-query", "cloudflare.com", wing::DNS_QTYPE_HTTPS, get_url);
        sub.assert_true(ok_get, "build_doh_get_url succeeds");
        sub.assert_true(core::starts_with(get_url[..], "https://1.1.1.1/dns-query?dns="), "URL starts with endpoint and ?dns=");
    };
}

fn test_dns_cache_lifecycle(t: core::T&) {
    t.run("1. Freshness, Stale-While-Revalidate Window, and Expiration") { sub =>
        var cache = wing::new_dns_cache();

        var entry = wing::DnsCacheEntry { .. };
        entry.domain.append("api.example.com");
        entry.qtype = wing::DNS_QTYPE_A;
        entry.ipv4_hints.push(0x7F000001); // 127.0.0.1
        entry.inserted_at_sec = 1000;
        entry.ttl_sec = 60;
        entry.stale_ttl_sec = 300; // Stale window: 1060 .. 1360
        entry.valid = true;

        wing::dns_cache_insert(cache, entry);
        sub.assert_eq(cache.entries.len, 1, "Cache holds 1 entry");

        // Lookup at t = 1030 (Fresh, elapsed 30 < 60)
        var out1 = wing::DnsCacheEntry { .. };
        let st1 = wing::dns_cache_lookup(cache, "api.example.com", wing::DNS_QTYPE_A, 1030, out1);
        sub.assert_eq(st1, wing::DnsCacheStatus.Fresh, "Lookup at t=1030 is Fresh");
        sub.assert_eq(out1.ipv4_hints.len, 1, "Output holds 1 IP");
        sub.assert_eq(out1.ipv4_hints[0], 0x7F000001, "IP matches");

        // Lookup at t = 1100 (Stale, elapsed 100 >= 60 but < 360)
        var out2 = wing::DnsCacheEntry { .. };
        let st2 = wing::dns_cache_lookup(cache, "api.example.com", wing::DNS_QTYPE_A, 1100, out2);
        sub.assert_eq(st2, wing::DnsCacheStatus.Stale, "Lookup at t=1100 is Stale");

        // Lookup at t = 1400 (Expired, elapsed 400 >= 360)
        var out3 = wing::DnsCacheEntry { .. };
        let st3 = wing::dns_cache_lookup(cache, "api.example.com", wing::DNS_QTYPE_A, 1400, out3);
        sub.assert_eq(st3, wing::DnsCacheStatus.Expired, "Lookup at t=1400 is Expired");

        // Overwrite existing entry with refreshed TTL
        var updated = entry;
        updated.inserted_at_sec = 1400;
        updated.ttl_sec = 120;
        wing::dns_cache_insert(cache, updated);
        sub.assert_eq(cache.entries.len, 1, "Cache still holds 1 entry after update");

        var out4 = wing::DnsCacheEntry { .. };
        let st4 = wing::dns_cache_lookup(cache, "api.example.com", wing::DNS_QTYPE_A, 1450, out4);
        sub.assert_eq(st4, wing::DnsCacheStatus.Fresh, "Lookup after refresh is Fresh");
    };
}

fn main() {
    var runner = core::new_runner("RFC 9460 HTTPS/SVCB & ECH Service Discovery Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9460 HTTPS/SVCB Parameter Parsing", test_rfc9460_svcb_https_rdata);
    core::run_case(runner, "2. DoH Query Serialization", test_doh_query_generation);
    core::run_case(runner, "3. DNS Cache Lifecycle & Stale-While-Revalidate", test_dns_cache_lifecycle);
    let ok = core::finish(runner);
    assert(ok);
}
