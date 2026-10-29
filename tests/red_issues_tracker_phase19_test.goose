// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 19 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. Chunk Extension Length Overhead Defense in ChunkFsmDecoder (CVE-2023-39326, Go #64433, RFC 9112 §7.1.1)
// 2. Chunk Trailer Length & Memory Flood Defense in ChunkFsmDecoder (CVE-2023-39326, RFC 9112 §7.1.2)
// 3. TLS 1.3 Cookie Extension Length Validation (RFC 8446 §4.2.2, OpenSSL #30868)
// 4. TLS 1.3 CertificateRequest certificate_authorities Extension Vector Validation (RFC 8446 §4.2.4, OpenSSL #32211)
// 5. Cookie Ingestion Quota Enforcement in Netscape Import (Go #75672, CVE-2025-58186)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Chunk Extension Length Overhead Defense (CVE-2023-39326, Go #64433)
// ----------------------------------------------------------------------------
fn test_chunk_fsm_extension_length_defense(t: core::T&) {
    t.run("ChunkFsmDecoder rejects chunk extension exceeding 1024 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();

        // Build chunk header with extension > 1024 bytes: "5;ext=" + 1025 'a's + "\r\nhello\r\n0\r\n\r\n"
        var raw: u8[>..] = [];
        raw.append("5;ext=");
        for _ in 1025 {
            raw.push('a');
        }
        raw.append("\r\nhello\r\n0\r\n\r\n");

        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Oversized chunk extension must trigger Error");
        sub.assert_eq(dec.state, internal::CHUNK_STATE_IS_ERROR, "FSM state must transition to sticky Error");
    };

    t.run("ChunkFsmDecoder accepts valid chunk extension <= 1024 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "5;ext=valid\r\nhello\r\n0\r\n\r\n";
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.YieldChunk, "Valid chunk extension accepted");
        sub.assert_bytes_eq(chunk, "hello", "Chunk payload yielded correctly");
    };
}

// ----------------------------------------------------------------------------
// 2. Chunk Trailer Length & Memory Flood Defense (CVE-2023-39326, RFC 9112 §7.1.2)
// ----------------------------------------------------------------------------
fn test_chunk_fsm_trailer_flood_defense(t: core::T&) {
    t.run("ChunkFsmDecoder rejects total trailer bytes exceeding 4096 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();

        // Stream final chunk "0\r\n", followed by oversized trailer line > 4096 bytes
        var raw: u8[>..] = [];
        raw.append("0\r\nX-Trailer: ");
        for _ in 4100 {
            raw.push('b');
        }
        raw.append("\r\n\r\n");

        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Oversized trailers > 4096 bytes must trigger Error");
        sub.assert_eq(dec.state, internal::CHUNK_STATE_IS_ERROR, "FSM state must transition to sticky Error");
    };

    t.run("ChunkFsmDecoder accepts legitimate trailers <= 4096 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "0\r\nX-Checksum: deadbeef\r\n\r\n";
        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.Complete, "Legitimate trailers succeed with Complete");
    };
}

// ----------------------------------------------------------------------------
// 3. TLS 1.3 Cookie Extension Length Validation (RFC 8446 §4.2.2, OpenSSL #30868)
// ----------------------------------------------------------------------------
fn test_tls13_cookie_extension_validation(t: core::T&) {
    t.run("Cookie extension with zero-length vector (empty) MUST be rejected") { sub =>
        // cookie<1..2^16-1>: vector length 0 is strictly forbidden by RFC 8446 Section 4.2.2
        let empty_cookie: u8[2] = [0x00, 0x00];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(empty_cookie[..], out);
        sub.assert_false(ok, "Zero-length cookie vector must be rejected");
    };

    t.run("Cookie extension with truncated payload MUST be rejected") { sub =>
        // Advertises 4 bytes but only 2 present
        let trunc_cookie: u8[4] = [0x00, 0x04, 0xAA, 0xBB];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(trunc_cookie[..], out);
        sub.assert_false(ok, "Truncated cookie payload must be rejected");
    };

    t.run("Cookie extension with trailing bytes MUST be rejected") { sub =>
        // Advertises 2 bytes but 3 bytes present in extension
        let trailing_cookie: u8[5] = [0x00, 0x02, 0xAA, 0xBB, 0xFF];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(trailing_cookie[..], out);
        sub.assert_false(ok, "Trailing bytes after cookie vector must be rejected");
    };

    t.run("Valid Cookie extension succeeds") { sub =>
        let valid_cookie: u8[6] = [0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(valid_cookie[..], out);
        sub.assert_true(ok, "Valid cookie extension parsed successfully");
        sub.assert_eq(out.len, 4, "Extracted 4-byte cookie");
        let expected: u8[4] = [0x01, 0x02, 0x03, 0x04];
        sub.assert_bytes_eq(out[..], expected[..], "Cookie contents match");
    };
}

// ----------------------------------------------------------------------------
// 4. TLS 1.3 CertificateRequest certificate_authorities Extension (RFC 8446 §4.2.4, OpenSSL #32211)
// ----------------------------------------------------------------------------
fn test_tls13_cert_authorities_extension_validation(t: core::T&) {
    t.run("certificate_authorities extension with empty vector (< 3 bytes) MUST be rejected") { sub =>
        // authorities<3..2^16-1>: length 0 is strictly forbidden by RFC 8446 Section 4.2.4
        let empty_ca: u8[2] = [0x00, 0x00];
        let ok = wing::validate_certificate_authorities_extension(empty_ca[..]);
        sub.assert_false(ok, "Empty authorities vector must be rejected");
    };

    t.run("certificate_authorities extension with vector length < 3 MUST be rejected") { sub =>
        // authorities vector length 2 (less than lower bound 3)
        let short_ca: u8[4] = [0x00, 0x02, 0x00, 0x00];
        let ok = wing::validate_certificate_authorities_extension(short_ca[..]);
        sub.assert_false(ok, "Authorities vector length < 3 must be rejected");
    };

    t.run("certificate_authorities extension with valid DN succeeds") { sub =>
        // authorities vector length = 5: one DN with length = 3 ("ABC")
        let valid_ca: u8[7] = [0x00, 0x05, 0x00, 0x03, 'A', 'B', 'C'];
        let ok = wing::validate_certificate_authorities_extension(valid_ca[..]);
        sub.assert_true(ok, "Valid authorities vector accepted");
    };

    t.run("CertificateRequest message with empty certificate_authorities MUST be rejected") { sub =>
        // Build CertificateRequest:
        // context_length: 0 (1B)
        // extensions_length: 6 (2B)
        // [ext 47 (2B: 0x00, 0x2F), ext_len 2 (2B: 0x00, 0x02), authorities_len 0 (2B: 0x00, 0x00)]
        // + signature_algorithms (type 13, len 4: list_len 2, ecdsa_secp256r1_sha256 0x0403)
        var msg: u8[..64] = [];
        msg.push(0x00); // context len 0
        // extensions length: 6 (CA) + 8 (sig_algs) = 14 (0x00, 0x0E)
        msg.push(0x00); msg.push(0x0E);
        // EXT_CERTIFICATE_AUTHORITIES (47 = 0x002F), ext_data_len 2, authorities_len 0
        msg.push(0x00); msg.push(0x2F);
        msg.push(0x00); msg.push(0x02);
        msg.push(0x00); msg.push(0x00); // EMPTY authorities vector!
        // EXT_SIGNATURE_ALGORITHMS (13 = 0x000D), ext_data_len 4, list_len 2, 0x0403
        msg.push(0x00); msg.push(0x0D);
        msg.push(0x00); msg.push(0x04);
        msg.push(0x00); msg.push(0x02);
        msg.push(0x04); msg.push(0x03);

        var parsed = wing::CertificateRequestMsg { .. };
        let ok = wing::parse_certificate_request(msg[..], false, parsed);
        sub.assert_false(ok, "CertificateRequest with empty certificate_authorities MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. Cookie Ingestion Quota Enforcement in Netscape Import (Go #75672, CVE-2025-58186)
// ----------------------------------------------------------------------------
fn test_cookie_import_cap_defense(t: core::T&) {
    t.run("import_netscape caps cookies at K_MAX_COOKIES to prevent memory/CPU exhaustion") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // Generate 3500 valid Netscape cookie lines:
        // domain \t flag \t path \t secure \t expiration \t name \t value \n
        var content: u8[>..] = [];
        for i in 3500 {
            content.append("example.com\tTRUE\t/\tFALSE\t2000000000\tc");
            var num_buf: u8[..16] = [];
            core::format_i64_dec(i, num_buf);
            content.append(num_buf[..]);
            content.append("\tv\n");
        }

        let imported = wing::import_netscape(jar, content[..], 1000000);
        sub.assert_true(imported <= 3300, "Imported cookies must not exceed K_MAX_COOKIES ceiling (3300)");
        sub.assert_true(imported >= 3000, "Should import up to capacity");
    };
}

// ----------------------------------------------------------------------------
// Test Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Phase 19 RED Issues Tracker Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Chunk Extension Length Overhead Defense", test_chunk_fsm_extension_length_defense);
    core::run_case(runner, "2. Chunk Trailer Length Flood Defense", test_chunk_fsm_trailer_flood_defense);
    core::run_case(runner, "3. TLS 1.3 Cookie Extension Length Validation", test_tls13_cookie_extension_validation);
    core::run_case(runner, "4. TLS 1.3 CertificateRequest certificate_authorities Extension", test_tls13_cert_authorities_extension_validation);
    core::run_case(runner, "5. Cookie Ingestion Quota Enforcement in Netscape Import", test_cookie_import_cap_defense);
}
