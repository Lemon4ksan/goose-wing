// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC & Cross-Component Regression Suite for core/
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "../..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_math_and_crypto_regressions(t: lit::T&) {
    t.run("Bug A1: ct_min_i64 / ct_max_i64 / ct_min_i32 / ct_max_i32 signed overflow at I64_MIN") { sub =>
        sub.assert_eq(core::ct_min_i64(core::I64_MIN, 0), core::I64_MIN, "ct_min_i64(I64_MIN, 0)");
        sub.assert_eq(core::ct_max_i64(core::I64_MIN, 0), 0, "ct_max_i64(I64_MIN, 0)");
        sub.assert_eq(core::ct_min_i64(core::I64_MAX, -1), -1, "ct_min_i64(I64_MAX, -1)");
        sub.assert_eq(core::ct_max_i64(core::I64_MAX, -1), core::I64_MAX, "ct_max_i64(I64_MAX, -1)");
        sub.assert_eq(core::ct_min_i32(core::I32_MIN, 0), core::I32_MIN, "ct_min_i32(I32_MIN, 0)");
        sub.assert_eq(core::ct_max_i32(core::I32_MIN, 0), 0, "ct_max_i32(I32_MIN, 0)");
        sub.assert_eq(core::retry_after_sec_to_ms_sat(core::I64_MIN), 0, "retry_after_sec_to_ms_sat(I64_MIN)");
        sub.assert_eq(core::clamp_happy_eyeballs_delay_ms(core::I64_MIN, false), 10, "clamp_happy_eyeballs_delay_ms(I64_MIN)");
    };

    t.run("Bug A2: backoff_decorrelated_jitter_ms respects cap_ms when cap_ms < base_ms") { sub =>
        var rng = core::new_wyrand(12345);
        let res = core::backoff_decorrelated_jitter_ms(rng, 1000, 500, 1000);
        sub.assert_true(res <= 500, "backoff_decorrelated_jitter_ms must not exceed cap_ms");
    };

    t.run("Bug A3: RFC 6979 int2octets(x) & bits2octets(h1) reduction in ecdsa_p256_sign and DER decode bounds") { sub =>
        // priv_key1 = P256_ORDER + 1 = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552
        let priv_key1: u8[32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x52,
        ];
        // priv_key2 = 1 (identical mod P256_ORDER)
        var priv_key2: u8[32] = [0; 32];
        priv_key2[31] = 1;
        let sig1 = core::ecdsa_p256_sign(priv_key1, "rfc6979-test");
        let sig2 = core::ecdsa_p256_sign(priv_key2, "rfc6979-test");
        sub.assert_eq(sig1[..], sig2[..], "RFC 6979 produces identical deterministic k for d and d mod q");

        // DER decode must reject r = 0 or s = 0
        let der_zero_r: u8[8] = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        var raw_out: u8[64] = [0; 64];
        sub.assert_false(core::ecdsa_p256_decode_der_sig(der_zero_r[..], raw_out), "DER sig with r=0 rejected");
    };

    t.run("Bug A4: RSASSA-PSS encode_emsa_pss / verify_emsa_pss with non-MSB-aligned modulus (mod_first_byte = 0x40)") { sub =>
        var msg_hash: u8[32]    = [0x42; 32];
        var salt:     u8[32]    = [0x11; 32];
        var em:       u8[..512] = [];
        // em_len = 128, mod_first_byte = 0x40 (1023-bit RSA modulus: 1 leading zero bit)
        let ok_enc = core::encode_emsa_pss(msg_hash[..], salt[..], 128, 0x40, em);
        sub.assert_true(ok_enc, "encode_emsa_pss accepts 1023-bit modulus (mod_first_byte = 0x40)");
        if ok_enc {
            sub.assert_eq(em[0] & 0xC0, 0, "top 2 bits of EM[0] masked to zero for mod_first_byte = 0x40");
            let ok_ver = core::verify_emsa_pss(em[..], msg_hash[..], 0x40);
            sub.assert_true(ok_ver, "verify_emsa_pss accepts valid 1023-bit PSS encoding");
        }
    };

    t.run("Bug D4: equal_short on slices > 32 bytes checks middle bytes") { sub =>
        let a = "0123456789abcdef_MIDDLE_A_0123456789abcdef";
        let b = "0123456789abcdef_MIDDLE_B_0123456789abcdef";
        sub.assert_false(core::equal_short(a, b), "equal_short detects difference in middle of 42-byte slice");
    };
}

fn test_compress_and_time_regressions(t: lit::T&) {
    t.run("Bug B1: Zstd fast sequence decoder with RLE_Mode FSE table (table_log == 0) and >= 4 sequences") { sub =>
        // Craft a valid Zstd frame where LL, OF, ML tables use RLE_Mode (table_log == 0), nb_seq = 4, and seq_bitstream >= 8 bytes
        // Block_Size = 18 -> (18 << 3) | 5 = 0x95
        let frame2: u8[27] = [
            0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00,
            0x95, 0x00, 0x00,
            0x20, 0x41, 0x42, 0x43, 0x44,
            0x04, 0x54, 0x01, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
        ];
        var out: u8[..64] = [];
        let ok, err = core::zstd_decompress(frame2[..], out);
        sub.assert_true(ok, "Zstd RLE_Mode sequence block with 4 sequences decompresses cleanly");
        sub.assert_eq(out[..], "AAAABBBBCCCCDDDD", "4 RLE sequences produce AAAABBBBCCCCDDDD");
    };

    t.run("Bug B2: zstd_decompress rejects 0-byte empty input") { sub =>
        var out: u8[..16] = [];
        let ok, err = core::zstd_decompress("", out);
        sub.assert_false(ok, "empty input is not a valid Zstd frame");
    };

    t.run("Bug B3: ZStreamDecompressor ContainerFormat.Auto decompresses short (<10B) Raw Deflate stream") { sub =>
        var raw_deflate: u8[..64] = [];
        let ok_c = core::deflate("Hi", raw_deflate);
        sub.assert_true(ok_c && raw_deflate.len < 10, "compressed 'Hi' is < 10 bytes");
        var dec = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        var out: u8[..64] = [];
        let err_d = core::zstream_decompress_write_limit(dec, raw_deflate[..], out, 64);
        sub.assert_true(err_d == core::CompressError.None && dec.is_finished, "Auto-detected short raw deflate finishes");
        sub.assert_eq(out[..], "Hi", "decompressed short raw deflate matches 'Hi'");
    };

    t.run("Bug B4: ZStreamDecompressor Concatenated Multi-Member Gzip Streams (RFC 1952 §2.2)") { sub =>
        var gz1: u8[..128] = [];
        var gz2: u8[..128] = [];
        let ok1 = core::gzip_compress("Hello ", gz1);
        let ok2 = core::gzip_compress("World!", gz2);
        sub.assert_true(ok1 && ok2, "both gzip members compressed");
        var combined: u8[..256] = [];
        combined.append(gz1[..]);
        combined.append(gz2[..]);
        var dec = core::new_zstream_decompressor(core::ContainerFormat.Gzip);
        var out: u8[..128] = [];
        let err_d = core::zstream_decompress_write_limit(dec, combined[..], out, 128);
        sub.assert_true(err_d == core::CompressError.None && dec.is_finished, "concatenated gzip members decompress cleanly");
        sub.assert_eq(out[..], "Hello World!", "concatenated gzip output matches both members");
    };

    t.run("Bug B5: ZStreamCompressor / ZStreamDecompressor preserve preset dict across sync-flush blocks") { sub =>
        let dict = "SHARED_PREFIX_DICTIONARY_TOKEN_1234567890_";
        var comp = core::new_zstream_compressor(core::ContainerFormat.Raw, 6);
        core::zstream_set_dictionary(comp, dict);
        var wire1: u8[..256] = [];
        var wire2: u8[..256] = [];
        let ok_w1 = core::zstream_write(comp, "first_chunk_", wire1);
        let ok_f1 = core::zstream_sync_flush(comp, wire1);
        let ok_w2 = core::zstream_write(comp, "SHARED_PREFIX_DICTIONARY_TOKEN_1234567890_end", wire2);
        let ok_fin = core::zstream_finish(comp, wire2);
        sub.assert_true(ok_w1 && ok_f1 && ok_w2 && ok_fin, "multi-block dict stream compressed");

        var dec = core::new_zstream_decompressor(core::ContainerFormat.Raw, dict);
        var out: u8[..512] = [];
        let err_d1 = core::zstream_decompress_write_limit(dec, wire1[..], out, 512);
        let err_d2 = core::zstream_decompress_write_limit(dec, wire2[..], out, 512);
        sub.assert_true(err_d1 == core::CompressError.None && err_d2 == core::CompressError.None && dec.is_finished, "multi-block dict stream decompressed across flush boundary");
        sub.assert_eq(out[..], "first_chunk_SHARED_PREFIX_DICTIONARY_TOKEN_1234567890_end", "decompressed multi-block dict payload matches");
    };

    t.run("Bug D1-D3: Time negative rounding, format_duration sub-ms precision, and RFC 9110 §5.6.7 HTTP-date") { sub =>
        // -0.1s (wall_sec = -1, nsec = 900_000_000) rounded to 1s must be 0s, not -1s
        let t_neg = core::unix(-1, 900000000);
        let r_neg = t_neg.round(core::secs(1));
        sub.assert_eq(r_neg.wall_sec, 0, "round(-0.1s, 1s) == 0s");
        sub.assert_eq(r_neg.nsec, 0, "round(-0.1s, 1s) nsec == 0");

        // 1.0005ms (1_000_500ns) formatted and parsed back must preserve 500ns
        let d_ms = core::nanos(1000500);
        var fmt_ms: u8[..64] = [];
        core::format(fmt_ms, d_ms);
        let parsed_ms, ok_p = core::parse_duration(fmt_ms[..]);
        sub.assert_true(ok_p, "format_duration output parses");
        sub.assert_eq(parsed_ms.nanos, 1000500, "format_duration preserves nanosecond precision for ms range");

        // parse_duration on DURATION_MIN_FORMATTED
        let min_d, ok_min = core::parse_duration(core::DURATION_MIN_FORMATTED);
        sub.assert_true(ok_min, "DURATION_MIN_FORMATTED parses cleanly");
        sub.assert_eq(min_d.nanos, core::DURATION_MIN_NANOS, "DURATION_MIN_FORMATTED round-trips");

        // RFC 9110 §5.6.7 HTTP-date strict grammar
        let t_bad1, ok_b1 = core::parse_http_date("Sun, 06-Nov-94 08:49:37 GMT");
        sub.assert_false(ok_b1, "rfc850-date must reject 3-letter day-name");
        let t_bad2, ok_b2 = core::parse_http_date("Sun,06 Nov 1994 08:49:37 GMT");
        sub.assert_false(ok_b2, "IMF-fixdate must require SP after comma");
    };
}

fn test_url_regressions(t: lit::T&) {
    t.run("Bug C1: file://LOCALHOST case-insensitive folding and file: port rejection") { sub =>
        let u_file, err_f = core::parse_url("file://LOCALHOST/etc/hosts");
        sub.assert_true(u_file.valid, "file://LOCALHOST/etc/hosts is valid");
        sub.assert_eq(core::host(u_file), "", "file://LOCALHOST folds to empty host");
        sub.assert_eq(core::href(u_file), "file:///etc/hosts", "href normalized to file:///etc/hosts");

        let u_fport, err_fp = core::parse_url("file://example.com:8080/path");
        sub.assert_false(u_fport.valid, "file: URL with port must be rejected");
    };

    t.run("Bug C2: Non-special authority-less path starting with // prepends /. (WHATWG URL §4.5 / RFC 3986 §3.3)") { sub =>
        let u_ns, err_ns = core::parse_url("custom:/.//evil.com/path");
        sub.assert_true(u_ns.valid, "custom:/.//evil.com/path parses");
        sub.assert_true(u_ns.host_start < 0, "no authority on initial parse");
        let u_reparsed, err_re = core::parse_url(core::href(u_ns));
        sub.assert_true(u_reparsed.host_start < 0, "re-parsing href must not promote evil.com to authority");
        sub.assert_eq(core::host(u_reparsed), "", "re-parsed host remains empty");
    };

    t.run("Bug C3: Relative resolution with same special scheme and 0 slashes (http:g, http:?q)") { sub =>
        let base, err_b = core::parse_url("http://example.com/dir/page.html");
        let rel_g = core::resolve_reference(base, "http:sub.html");
        sub.assert_true(rel_g.valid, "http:sub.html resolves against base");
        sub.assert_eq(core::href(rel_g), "http://example.com/dir/sub.html", "http:sub.html resolved relative to base");
    };

    t.run("Bug C4: IPv6 ZoneID in registrable_site_from_url and blob: inner URL unwrapping") { sub =>
        let u_v6, err_6 = core::parse_url("http://[fe80::1%25eth0]:8080/index.html");
        let orig_v6 = core::origin_from_url(u_v6);
        sub.assert_true(core::is_same_site_origin_url(orig_v6, u_v6), "origin_from_url and registrable_site_from_url agree on scoped IPv6");

        let u_blob, err_bl = core::parse_url("blob:https://app.example.com/550e8400-e29b-41d4-a716-446655440000");
        let u_https, err_ht = core::parse_url("https://api.example.com/v1");
        sub.assert_true(core::is_schemeful_same_site_urls(u_blob, u_https), "blob:https://app.example.com is same-site with https://api.example.com");
    };

    t.run("Bug C5 & C6: normalize_http_target_uri empty host & query percent-encoded key matching") { sub =>
        var norm_out: u8[..128] = [];
        let ok_empty_host = core::normalize_http_target_uri("http://:80/path", norm_out);
        sub.assert_false(ok_empty_host, "http://:80/path with empty host rejected");

        let q_toks = core::parse_query_params("a%20b=1&x=2");
        sub.assert_false(core::has_query_param(q_toks, "a%20b"), "decoded key 'a b' must not match literal 'a%20b'");
        sub.assert_true(core::has_query_param(q_toks, "a b"), "decoded key 'a b' matches 'a b'");
        sub.assert_false(core::validate_query_param_count("a=1", 0), "validate_query_param_count('a=1', 0) must return false");

        var dec_small: u8[..4] = [];
        let ok_dec = core::percent_decode("%41%42%43%44", dec_small);
        sub.assert_true(ok_dec && dec_small[..] == "ABCD", "percent_decode succeeds when decoded length fits capacity");
    };
}

fn main() {
    var runner = lit::new_runner("Core Cross-Component & RFC Edge Case Regressions", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. Math & Crypto Regressions", test_math_and_crypto_regressions);
    lit::run_case(runner, "2. Compress & Time Regressions", test_compress_and_time_regressions);
    lit::run_case(runner, "3. URL Regressions", test_url_regressions);
    let ok = lit::finish(runner);
    assert(ok);
}
