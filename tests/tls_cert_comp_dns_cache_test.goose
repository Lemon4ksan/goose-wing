// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite for RFC 8879 (TLS Certificate Compression via Zstandard),
// TLS ClientHello Fragmentation, and DNS Cache with Stale-While-Revalidate.
import std;
import core from "..";
import wing from "..";

fn test_rfc8879_certificate_compression(t: core::T&) {
    t.run("1. RFC 8879 Extension & Handshake Message Codecs") { sub =>
        let algos: u16[2] = [wing::CERT_COMPRESS_ZSTD, wing::CERT_COMPRESS_BROTLI];
        var ext_wire: u8[>..] = [];
        wing::encode_compress_certificate_extension(ext_wire, algos[..]);

        sub.assert_eq(ext_wire.len, 2 + 2 + 1 + 4, "Extension wire length: 2 type + 2 len + 1 list_len + 4 algorithms = 9 bytes");
        let ext_type = ((ext_wire[0] as u16) << 8) | ext_wire[1];
        sub.assert_eq(ext_type, wing::EXT_COMPRESS_CERTIFICATE, "Extension type is 27 (compress_certificate)");

        // Handshake payload roundtrip
        let fake_cert = "MIIB...Simulated X.509 Certificate Chain Data with Repetitive Certificate Metadata Blocks...";
        var compressed: u8[>..] = [];
        sub.assert_true(core::zstd_compress(fake_cert, compressed), "Zstandard compression of certificate succeeds");

        var hs_payload: u8[>..] = [];
        wing::encode_compressed_certificate_payload(
            hs_payload,
            wing::CERT_COMPRESS_ZSTD,
            fake_cert.len as u32,
            compressed[..],
        );

        let parsed, ok_parse = wing::parse_compressed_certificate(hs_payload[..]);
        sub.assert_true(ok_parse, "Parse CompressedCertificate payload");
        sub.assert_eq(parsed.algorithm, wing::CERT_COMPRESS_ZSTD, "Algorithm is Zstandard (3)");
        sub.assert_eq(parsed.uncompressed_len as i64, fake_cert.len as i64, "Uncompressed length matches original");

        // Decompress with native RFC 8878 Zstandard engine
        var decompressed: u8[>..] = [];
        sub.assert_true(wing::decompress_certificate_zstd(parsed.compressed_data, parsed.uncompressed_len, decompressed), "Decompression succeeds");
        sub.assert_bytes_eq(decompressed[..], fake_cert, "Decompressed certificate matches original plaintext exactly");
    };
}

fn test_tls_client_hello_fragmentation(t: core::T&) {
    t.run("1. ClientHello Record Fragmentation for Anti-Censorship / DPI Evasion") { sub =>
        let dummy_ch = "ClientHelloPayloadContainingServerNameIndicationSNIAndCiphersAndExtensionsForTesting";
        var records: u8[>..] = [];

        let split_point: i64 = 20;
        sub.assert_true(wing::fragment_client_hello(dummy_ch, split_point, records), "fragment_client_hello succeeds");

        // Record 1: 5 bytes header + 20 bytes data = 25 bytes
        sub.assert_eq(records[0], 22, "Record 1 content type is Handshake (22)");
        sub.assert_eq(records[1], 0x03, "Record 1 legacy major 3");
        sub.assert_eq(records[2], 0x01, "Record 1 legacy minor 1 (TLS 1.0)");
        let len1 = ((records[3] as i64) << 8) | (records[4] as i64);
        sub.assert_eq(len1, 20, "Record 1 payload length is 20");
        sub.assert_bytes_eq(records[5..25], dummy_ch[..20], "Record 1 payload matches first slice");

        // Record 2: 5 bytes header + (total - 20) bytes data
        let rec2_start = 25;
        sub.assert_eq(records[rec2_start], 22, "Record 2 content type is Handshake (22)");
        let len2 = ((records[rec2_start + 3] as i64) << 8) | (records[rec2_start + 4] as i64);
        sub.assert_eq(len2, dummy_ch.len - 20, "Record 2 payload length matches remainder");
        sub.assert_bytes_eq(records[rec2_start + 5..], dummy_ch[20..], "Record 2 payload matches remainder");

        // Invariant: Total payload concatenated across records exactly equals original message
        var reassembled: u8[>..] = [];
        reassembled.append(records[5..25]);
        reassembled.append(records[rec2_start + 5..]);
        sub.assert_bytes_eq(reassembled[..], dummy_ch, "Reassembled handshake records exactly equal original ClientHello");
    };
}

fn test_dns_cache_and_stale_revalidate(t: core::T&) {
    t.run("1. DNS Cache TTL and Stale-While-Revalidate Lifecycle") { sub =>
        var cache = wing::new_dns_cache();

        var entry = wing::DnsCacheEntry {
            qtype: wing::DNS_QTYPE_A,
            inserted_at_sec: 1000,
            ttl_sec: 300,        // 5 minutes
            stale_ttl_sec: 3600, // 1 hour grace period
            ..
        };
        entry.domain.append("example.com");
        entry.ipv4_hints.push(0x5DB8D822); // 93.184.216.34

        wing::dns_cache_insert(cache, entry);

        // 1. Fresh lookup at t = 1100 (100s elapsed < 300s TTL)
        var hit1 = wing::DnsCacheEntry { .. };
        let status1 = wing::dns_cache_lookup(cache, "example.com", wing::DNS_QTYPE_A, 1100, hit1);
        sub.assert_eq(status1, wing::DnsCacheStatus.Fresh, "Lookup within TTL returns Fresh");
        sub.assert_eq(hit1.ipv4_hints[0], 0x5DB8D822, "Cached IPv4 address preserved");

        // 2. Stale lookup at t = 1500 (500s elapsed > 300s TTL, but < 3900s stale limit)
        var hit2 = wing::DnsCacheEntry { .. };
        let status2 = wing::dns_cache_lookup(cache, "example.com", wing::DNS_QTYPE_A, 1500, hit2);
        sub.assert_eq(status2, wing::DnsCacheStatus.Stale, "Lookup past TTL returns Stale (trigger background revalidation)");
        sub.assert_eq(hit2.ipv4_hints[0], 0x5DB8D822, "Stale cache hit still provides IP for zero-latency connection");

        // 3. Expired lookup at t = 5000 (4000s elapsed > 3900s total limit)
        var hit3 = wing::DnsCacheEntry { .. };
        let status3 = wing::dns_cache_lookup(cache, "example.com", wing::DNS_QTYPE_A, 5000, hit3);
        sub.assert_eq(status3, wing::DnsCacheStatus.Expired, "Lookup beyond stale window returns Expired");

        // 4. Missing domain lookup
        var hit4 = wing::DnsCacheEntry { .. };
        let status4 = wing::dns_cache_lookup(cache, "notfound.org", wing::DNS_QTYPE_A, 1100, hit4);
        sub.assert_eq(status4, wing::DnsCacheStatus.Expired, "Missing domain returns Expired");
    };
}

fn main() {
    var runner = core::new_runner("TLS Certificate Compression, Fragmentation & DNS Cache Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 8879 TLS Certificate Compression via Zstandard", test_rfc8879_certificate_compression);
    core::run_case(runner, "2. TLS ClientHello Fragmentation & DPI Evasion", test_tls_client_hello_fragmentation);
    core::run_case(runner, "3. DNS Cache with Stale-While-Revalidate", test_dns_cache_and_stale_revalidate);

    let ok = core::finish(runner);
    assert(ok);
}
