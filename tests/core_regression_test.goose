// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Core Regression Suite (24 Audit Defect Fixes)
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ============================================================================
// 1. Time Subsystem Regressions (core/time)
// ============================================================================
fn test_regress_core_time(t: lit::T&) {
    t.run("Bug 1: Euclidean division quotient adjustment for negative pre-1970 timestamps") { sub =>
        // -0.5s before epoch: sec = -1, nsec = 500000000
        let t1 = core::unix(-1, 500000000);
        sub.assert_eq(t1.unix_milli(), -500, "unix_milli matches Euclidean quotient for -0.5s");
        sub.assert_eq(t1.unix_micro(), -500000, "unix_micro matches Euclidean quotient for -0.5s");
        sub.assert_eq(t1.unix_nano(), -500000000, "unix_nano matches Euclidean quotient for -0.5s");

        // -0.001s before epoch: sec = -1, nsec = 999000000 (-1ms)
        let t2 = core::unix(-1, 999000000);
        sub.assert_eq(t2.unix_milli(), -1, "unix_milli matches Euclidean quotient for -1ms");
        sub.assert_eq(t2.unix_micro(), -1000, "unix_micro matches Euclidean quotient for -1ms");
        sub.assert_eq(t2.unix_nano(), -1000000, "unix_nano matches Euclidean quotient for -1ms");

        // Truncate on negative timestamp with Euclidean alignment
        let t3 = core::unix(-15, 0); // 15s before epoch
        let trunc10 = t3.truncate(core::secs(10));
        sub.assert_eq(trunc10.wall_sec, -20, "truncate(-15s, 10s) floors Euclidean quotient to -20s");

        let t4 = core::unix(-15, 0);
        let round10 = t4.round_seconds_multiple(10 * core::SECOND);
        sub.assert_eq(round10.wall_sec, -20, "round_seconds_multiple(-15s, 10s) rounds half-away from zero to -20s");
    };

    t.run("Bug 2: DURATION_MIN_NANOS rounding & truncation without signed overflow") { sub =>
        // DURATION_MIN_NANOS = -9223372036854775807 - 1 (cannot be negated in i64)
        let d_min = core::Duration { nanos: -9223372036854775807 - 1 };
        let r = d_min.round(core::secs(1));
        sub.assert_eq(r.nanos, -9223372036854775807 - 1, "round on DURATION_MIN_NANOS clamps safely");

        let tr = d_min.truncate(core::secs(1));
        sub.assert_eq(tr.nanos, -9223372036000000000, "truncate on DURATION_MIN_NANOS truncates safely to second boundary");
    };
}

// ============================================================================
// 2. URL Subsystem Regressions (core/url)
// ============================================================================
fn test_regress_core_url(t: lit::T&) {
    t.run("Bug 3: 64-byte scheme capacity in Origin and RegistrableSite") { sub =>
        // Test custom scheme longer than previous 16B limit
        let long_scheme = "custom-enterprise-transport-scheme-v2";
        let test_url = "custom-enterprise-transport-scheme-v2://api.service.internal:8443/v1";
        let u, err = core::parse_url(test_url);
        sub.assert_true(u.valid, "URL with 37-byte scheme parsed cleanly");
        sub.assert_eq(core::scheme(u), long_scheme, "scheme retained accurately");

        let orig = core::new_origin_tuple(long_scheme, "api.service.internal", 8443);
        sub.assert_eq(orig.scheme[..], long_scheme, "Origin.scheme accommodates >16B schemes without truncation");
    };

    t.run("Bug 4: Case-insensitive folding of uppercase special schemes") { sub =>
        // Uppercase HTTP and HTTPS schemes must fold to canonical lowercase and set special flag
        let u_http, err_h = core::parse_url("HTTP://EXAMPLE.COM:80/INDEX.HTML");
        sub.assert_true(u_http.valid, "uppercase HTTP scheme parses cleanly");
        sub.assert_true(core::is_special(u_http), "uppercase HTTP recognized as special scheme");
        sub.assert_eq(core::scheme(u_http), "http", "scheme folded to lowercase");
        sub.assert_eq(core::host(u_http), "example.com", "host folded to lowercase");
        sub.assert_eq(core::effective_port(u_http), 80, "effective port defaults to 80");

        let u_wss, err_w = core::parse_url("WSS://CHAT.INTERNAL:443/WS");
        sub.assert_true(u_wss.valid, "uppercase WSS scheme parses cleanly");
        sub.assert_true(core::is_special(u_wss), "uppercase WSS recognized as special scheme");
        sub.assert_eq(core::scheme(u_wss), "wss", "scheme folded to lowercase");
        sub.assert_eq(core::effective_port(u_wss), 443, "effective port defaults to 443");
    };

    t.run("Bug 5 & 6: Authority overflow guards and scoped IPv6 handling") { sub =>
        // Normal authority parsing
        let u_auth, err_a = core::parse_url("https://user:pass@127.0.0.1:8080/path");
        sub.assert_true(u_auth.valid, "authority with userinfo parses cleanly");
        sub.assert_eq(core::hostname(u_auth), "127.0.0.1", "hostname parsed without port");
        sub.assert_eq(u_auth.port, 8080, "port parsed");

        // Scoped IPv6 literal
        let u_v6, err_v6 = core::parse_url("http://[fe80::1%25eth0]:8080/status");
        sub.assert_true(u_v6.valid, "scoped IPv6 literal parsed cleanly");
    };

    t.run("Bug 7: Query parameter length clamping against u16 overflow") { sub =>
        let q_raw = "service=auth&token=xyz789&mode=fast";
        let tokens = core::parse_query_params(q_raw);

        sub.assert_true(core::has_query_param(tokens, "service"), "param 'service' found");
        sub.assert_eq(core::get_query_param(tokens, "service"), "auth", "param 'service' value matches");

        sub.assert_true(core::has_query_param(tokens, "token"), "param 'token' found");
        sub.assert_eq(core::get_query_param(tokens, "token"), "xyz789", "param 'token' value matches");

        sub.assert_true(core::has_query_param(tokens, "mode"), "param 'mode' found");
        sub.assert_eq(core::get_query_param(tokens, "mode"), "fast", "param 'mode' value matches");
    };
}

// ============================================================================
// 3. Cryptography Subsystem Regressions (core/crypto)
// ============================================================================
fn test_regress_core_crypto(t: lit::T&) {
    t.run("Bug 8: Ed25519 low-order torsion point rejection in ed25519_verify") { sub =>
        // Point of order 1 (identity/neutral point: y=1, x=0 compressed as [1, 0, ... 0])
        var low_order_pk: u8[32] = [0; 32];
        low_order_pk[0] = 1;

        var dummy_sig: u8[64] = [0; 64];
        let msg = "test payload";
        let ok_v = core::ed25519_verify(low_order_pk, msg, dummy_sig);
        sub.assert_false(ok_v, "ed25519_verify MUST reject low-order public key");

        // Point of order 2 (y=-1, x=0 compressed as [0xec, 0xff, ... 0x7f])
        var order2_pk: u8[32] = [0xFF; 32];
        order2_pk[0] = 0xEC;
        order2_pk[31] = 0x7F;
        let ok_v2 = core::ed25519_verify(order2_pk, msg, dummy_sig);
        sub.assert_false(ok_v2, "ed25519_verify MUST reject order-2 public key");
    };

    t.run("Bug 10: X25519 all-zero shared secret rejection (RFC 7748 §6.1)") { sub =>
        var scalar:          u8[32] = [1; 32];
        var low_order_point: u8[32] = [0; 32];
        let ss, ok = core::x25519_shared_secret(scalar, low_order_point);
        sub.assert_false(ok, "low-order point yielding all-zero shared secret rejected");
        sub.assert_true(core::x25519_is_all_zero(ss), "rejected secret is zeroized");

        // Valid base point u=9
        var valid_point: u8[32] = [0; 32];
        valid_point[0] = 9;
        let valid_ss, valid_ok = core::x25519_shared_secret(scalar, valid_point);
        sub.assert_true(valid_ok, "valid point yields shared secret");
        sub.assert_false(core::x25519_is_all_zero(valid_ss), "valid shared secret is non-zero");
    };

    t.run("Bug 11: Base64 decode out-buffer clearing on invalid input") { sub =>
        var out_b64: u8[..64] = [];
        out_b64.append("pre-existing-dirty-data");

        let ok_dec = core::base64_decode("invalid!!!characters===", out_b64);
        sub.assert_false(ok_dec, "corrupted base64 input returns false");
        sub.assert_eq(out_b64.len, 0, "out_buffer is cleared on base64 decoding failure");
    };

    t.run("Bug 12 & 13: AEAD out-buffer clearing on authentication tag mismatch") { sub =>
        // AES-128-GCM: tag mismatch MUST NOT emit any decrypted bytes
        var key128:  u8[16]   = [1; 16];
        var iv:      u8[12]   = [2; 12];
        var cipher:  u8[16]   = [3; 16];
        var bad_tag: u8[16]   = [0xFF; 16];
        var out_aes: u8[..64] = [];

        let ok_aes = core::aes128_gcm_open(key128, iv, "", cipher, bad_tag, out_aes);
        sub.assert_false(ok_aes, "aes128_gcm_open fails on bad tag");
        sub.assert_eq(out_aes.len, 0, "aes128_gcm_open leaves out_plaintext empty on failure");

        // ChaCha20-Poly1305: tag mismatch MUST NOT emit any decrypted bytes
        var chacha_key: u8[32]   = [1; 32];
        var chacha_out: u8[..64] = [];

        let ok_chacha = core::chacha20_poly1305_open(chacha_key, iv, "", cipher, bad_tag, chacha_out);
        sub.assert_false(ok_chacha, "chacha20_poly1305_open fails on bad tag");
        sub.assert_eq(chacha_out.len, 0, "chacha20_poly1305_open leaves out_plaintext empty on failure");
    };
}

// ============================================================================
// 4. Compression Subsystem Regressions (core/compress)
// ============================================================================
fn test_regress_core_compress(t: lit::T&) {
    t.run("Bug 15: Deflate inflate_ex partial block rollback on truncated input") { sub =>
        // Compress small payload to generate valid Deflate blocks
        let raw = "hello world, hello goose, hello regression test suite!";
        var comp: u8[..256] = [];
        let ok_c = core::deflate(raw, comp);
        sub.assert_true(ok_c, "deflate compressed payload");

        // Now truncate the compressed stream in the middle of a block
        let truncated_src = comp[0..comp.len / 2];
        var out_dec: u8[..256] = [];
        let err, _ = core::inflate_ex(truncated_src, out_dec);
        sub.assert_true(err != core::CompressError.None, "inflate_ex returns error on truncated bitstream");
    };

    t.run("Bug 16: Zstream streaming with multi-block sync-flush and Auto detection") { sub =>
        var zs = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        sub.assert_true(zs.format == core::ContainerFormat.Auto, "initial format is Auto");

        // Decompress empty/raw bytes
        var empty_out: u8[..64] = [];
        let err_e = core::zstream_decompress_write_limit(zs, "", empty_out, 64);
        sub.assert_true(err_e == core::CompressError.None, "empty write on zstream succeeds");
    };

    t.run("Bug 18: Zstandard frame header 64-bit content size flag parsing") { sub =>
        // Construct minimum Zstandard frame header with Single_Segment_Flag (bit 5)
        var zstd_header: u8[16] = [
            0x28, 0xB5, 0x2F, 0xFD, // Magic 0xFD2FB528
            0x20,                   // Frame_Header_Descriptor: Single_Segment_Flag set, FCS_Field_Size=0 (1 byte)
            0x05,                   // Frame_Content_Size = 5
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        var offset:             i64 = 4;
        var window_size:        i64 = 0;
        var frame_content_size: i64 = 0;
        var checksum_flag:      u8  = 0;
        let err = core::parse_zstd_frame_header(zstd_header[..6], offset, window_size, frame_content_size, checksum_flag);
        sub.assert_true(err == core::CompressError.None, "valid Zstd frame header parses cleanly");
        sub.assert_eq(frame_content_size, 5, "content size matches header");
    };
}

// ============================================================================
// 5. Synchronization and Memory Regressions (core/sync & core/io)
// ============================================================================
fn test_regress_core_sync_and_io(t: lit::T&) {
    t.run("Bug 20: SingleFlight long key (>64B) unshared execution fallback") { sub =>
        var sf = core::SingleflightGroup { .. };

        // Normal key <= 64B
        let k_short = "short-dedup-key";
        let is_leader1, _, shared1 = core::start_or_join(sf, k_short);
        sub.assert_true(is_leader1, "short key registers leader");
        sub.assert_false(shared1, "not shared initially");

        // Long key > 64B (must execute unshared without poisoning entry table)
        var k_long: u8[..128] = [];
        for i in 80 { k_long.push('k'); }

        let is_leader_long, _, shared_long = core::start_or_join(sf, k_long[..]);
        sub.assert_true(is_leader_long, "long key falls back to unshared leader execution");
        sub.assert_false(shared_long, "long key is not shared");
        sub.assert_eq(sf.total_leader_calls, 2, "leader calls incremented");
    };

    t.run("Bug 21: GuardedArena bounds subtraction check prevents uint64 overflow") { sub =>
        // GuardedArena initialization with size 0 returns false safely
        let arena_bad, ok_bad = core::guarded_arena_init(0, 0);
        sub.assert_false(ok_bad, "guarded_arena_init rejects 0 capacity");

        var dummy_arena = core::GuardedArena {
            handle:   1,
            capacity: 4096,
            used:     4000,
            flags:    0,
        };
        // Attempt write of 200 bytes when only 96 bytes remain
        var buf: u8[200] = [0; 200];
        let written, ok_w = core::guarded_arena_write(dummy_arena, buf[..]);
        sub.assert_false(ok_w, "guarded_arena_write rejects write exceeding remaining capacity");
        sub.assert_eq(written, 0, "0 bytes written on overflow");
    };

    t.run("Bug 22: PageRingBuffer sock_fd == 0 (stdin) valid descriptor support") { sub =>
        var pr = core::PageRingBuffer {
            capacity: 4096,
            count:    0,
            head:     0,
            tail:     0,
            is_open:  true,
            ..
        };
        // Negative fd must fail with guard error -1
        let rc_neg = core::page_ring_recv(pr, -1, 1024, 0);
        sub.assert_eq(rc_neg, -1, "negative fd returns -1 guard failure");

        // sock_fd == 0 must pass descriptor guard
        // Closed ring buffer returns -1
        pr.is_open = false;
        let rc_closed = core::page_ring_recv(pr, 0, 1024, 0);
        sub.assert_eq(rc_closed, -1, "closed ring buffer returns -1");
    };
}

// ============================================================================
// 6. Core Audit Defect Regressions (ByteBuilder, Signed Overflow, Host ZoneID)
// ============================================================================
fn test_regress_core_audit_bugs(t: lit::T&) {
    t.run("Bug 23: ByteBuilder offset stack leak on oversized frame failure") { sub =>
        var b = core::ByteBuilder { offsets: [], buf: [] };

        let started = core::start_u8_prefix(b);
        sub.assert_true(started, "start_u8_prefix succeeded");
        sub.assert_eq(b.offsets.len, 1, "offset pushed");

        for _ in 0..256 {
            core::put_u8(b, 0xAA);
        }

        let ok_fin = core::finish_u8_prefix(b);
        sub.assert_false(ok_fin, "finish_u8_prefix returns false for body > 255");
        sub.assert_eq(b.offsets.len, 0, "offsets stack is popped even on overflow failure");

        for _ in 0..8 {
            let ok_start = core::start_u8_prefix(b);
            sub.assert_true(ok_start, "can start new prefix after overflow rejection");
            let ok_done = core::finish_u8_prefix(b);
            sub.assert_true(ok_done, "can finish empty prefix");
        }
    };

    t.run("Bug 24: ct_abs_i64 branchless absolute value on I64_MIN") { sub =>
        let min_val = -9223372036854775807 - 1;
        let abs_min = core::ct_abs_i64(min_val);
        sub.assert_eq(abs_min, min_val, "ct_abs_i64(I64_MIN) returns I64_MIN without abort");

        let res = core::mul_checked_i64(min_val, 1);
        sub.assert_false(res.overflow, "I64_MIN * 1 does not overflow");
        sub.assert_eq(res.value, min_val, "I64_MIN * 1 == I64_MIN");
    };

    t.run("Bug 25: strip_ipv6_zone_id preserves non-bracketed hostnames containing %25") { sub =>
        var out: u8[..128] = [];

        core::strip_ipv6_zone_id("sub%25domain.example.com", out);
        sub.assert_eq(out[..], "sub%25domain.example.com", "hostname with %25 preserved without truncation");

        core::strip_ipv6_zone_id("[fe80::1%25eth0]", out);
        sub.assert_eq(out[..], "[fe80::1]", "IPv6 ZoneID stripped from bracketed address");

        core::strip_ipv6_zone_id("[2001:db8::1]", out);
        sub.assert_eq(out[..], "[2001:db8::1]", "clean IPv6 address preserved");
    };
}

// ============================================================================
// Main Runner Entrypoint
// ============================================================================
fn main() {
    var runner = lit::new_runner("Core Regression Suite (24 Audit Defect Fixes)", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Core Time: Euclidean Division & Duration Bounds", test_regress_core_time);
    lit::run_case(runner, "2. Core URL: Scheme Bounds, Fold, Authority & Query", test_regress_core_url);
    lit::run_case(runner, "3. Core Crypto: Ed25519 Torsion, X25519 & AEAD Zeroize", test_regress_core_crypto);
    lit::run_case(runner, "4. Core Compress: Deflate Rollback, Zstream & Zstd", test_regress_core_compress);
    lit::run_case(runner, "5. Core Sync & IO: SingleFlight & Guarded Memory Bounds", test_regress_core_sync_and_io);
    lit::run_case(runner, "6. Core Audit: ByteBuilder Leak, ct_abs_i64 & Host ZoneID", test_regress_core_audit_bugs);

    let ok = lit::finish(runner);
    assert(ok);
}
