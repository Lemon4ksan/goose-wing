// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 11 RED test suite based on .gemini issue trackers, RFC specifications,
// and heapless fixed-capacity stack buffer (T[..N]) vulnerability research:
//
// 1. SignedJar HMAC cookie name context swapping (security/crypto_jar.goose)
// 2. RFC 9000 §4.5 QUIC FINAL_SIZE_ERROR on FIN less than buffered data (quic/packet.goose)
// 3. X.509 v3 explicit version tag parsing (tls/x509.goose)
// 4. Set-Cookie name length exceeding 256 bytes buffer bounds (cookie/parser.goose)
// 5. Set-Cookie Domain/Path attribute exceeding 256 bytes buffer bounds (cookie/parser.goose)
// 6. CSRF FetchContext method corruption and Origin concatenation (security/csrf.goose)
// 7. gRPC-Web trailers CRLF injection and buffer bounds (grpc/framing.goose)
// 8. Rate limiter KeyedGcraSlot key > 64 bytes buffer bounds (security/rate_limiter.goose)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. SignedJar HMAC Cookie Name Swapping (security/crypto_jar.goose)
// ----------------------------------------------------------------------------
fn test_signed_jar_cookie_name_swapping(t: core::T&) {
    t.run("SignedJar HMAC must bind cookie name to prevent context swapping") { sub =>
        var store = wing::new_key_store();
        var master: u8[32] = [0x42; 32];
        let slot = core::KeySlot {
            key_id: 1,
            master_key: master,
            created_at_sec: 1000,
            expires_at_sec: 2000000000,
            revoked: false,
        };
        let _ = wing::add_key(store, slot);
        let jar = wing::new_signed_jar(store);

        let cookie_name_1 = "role";
        let cookie_name_2 = "user"; // Same length (4 bytes), different semantics!
        let payload = "admin";
        let now_sec: i64 = 1700000000;

        var wire: u8[>..] = [];
        let ok_seal = wing::signed_jar_seal_binary(jar, cookie_name_1, payload, now_sec, wire);
        sub.assert_true(ok_seal, "SignedJar seal must succeed");

        // Legitimate verification with matching cookie name "role"
        var out_legit: u8[>..] = [];
        let ok_legit = wing::signed_jar_open_binary(jar, cookie_name_1, wire[..], now_sec, out_legit);
        sub.assert_true(ok_legit, "SignedJar open with matching cookie name must succeed");
        sub.assert_eq(out_legit[..], payload, "Payload must match sealed value");

        // Attacker attempts context swapping: presents the signature for cookie name "user"
        var out_swap: u8[>..] = [];
        let ok_swap = wing::signed_jar_open_binary(jar, cookie_name_2, wire[..], now_sec, out_swap);
        sub.assert_false(ok_swap, "SignedJar open with swapped cookie name 'user' MUST FAIL");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9000 §4.5 QUIC FINAL_SIZE_ERROR on FIN less than buffered data
// ----------------------------------------------------------------------------
fn test_quic_final_size_error_less_than_buffered(t: core::T&) {
    t.run("RFC 9000 §4.5: FIN at offset less than buffered data must trigger error") { sub =>
        var buf = wing::ReassemblyBuffer { .. };

        // 1. Receive data at offset 500 with length 500 (interval [500, 1000]), not fin
        let data1: u8[10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let ok1 = wing::insert_fragment(buf, 500, data1[..], false);
        sub.assert_true(ok1, "Initial out-of-order fragment must be buffered");

        // 2. Receive FIN at offset 0 with length 200 (frag_end = 200)
        // Since bytes up to 510 were already received, final size 200 is illegal!
        let ok2 = wing::insert_fragment(buf, 0, data1[..], true);
        sub.assert_false(ok2, "FIN declaring final_size < previously buffered data MUST return false (FINAL_SIZE_ERROR)");
    };
}

// ----------------------------------------------------------------------------
// 3. X.509 v3 Explicit Version Tag Parsing (tls/x509.goose)
// ----------------------------------------------------------------------------
fn test_x509_v3_version_parsing(t: core::T&) {
    t.run("X.509 v3 certificate with explicit [0] version tag must parse successfully") { sub =>
        // Minimal valid canonical DER X.509 v3 certificate:
        // SEQUENCE (Certificate)
        //   SEQUENCE (TBSCertificate)
        //     [0] EXPLICIT INTEGER 2 (v3) -> A0 03 02 01 02
        //     INTEGER (Serial) -> 02 01 01
        //     SEQUENCE (sig alg: ecdsa-with-SHA256: 1.2.840.10045.4.3.2) -> 30 0A 06 08 2A 86 48 CE 3D 04 03 02
        //     SEQUENCE (Issuer: empty sequence) -> 30 00
        //     SEQUENCE (Validity) -> 30 1E 17 0D 32 36 30 31 30 31 30 30 30 30 30 30 5A 17 0D 32 37 30 31 30 31 30 30 30 30 30 30 5A
        //     SEQUENCE (Subject: empty sequence) -> 30 00
        //     SEQUENCE (SPKI) -> 30 13 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 05 00 01 02 03 04
        //   SEQUENCE (sig alg: ecdsa-with-SHA256) -> 30 0A 06 08 2A 86 48 CE 3D 04 03 02
        //   BIT STRING (Signature) -> 03 05 00 AA BB CC DD

        var tbs: u8[>..] = [];
        // [0] EXPLICIT version v3 (0xA0 0x03 0x02 0x01 0x02)
        tbs.push(0xA0); tbs.push(0x03); tbs.push(0x02); tbs.push(0x01); tbs.push(0x02);
        // Serial: 0x02 0x01 0x01
        tbs.push(0x02); tbs.push(0x01); tbs.push(0x01);
        // Sig Alg: 30 0A 06 08 2A 86 48 CE 3D 04 03 02
        tbs.push(0x30); tbs.push(0x0A); tbs.push(0x06); tbs.push(0x08);
        tbs.push(0x2A); tbs.push(0x86); tbs.push(0x48); tbs.push(0xCE); tbs.push(0x3D); tbs.push(0x04); tbs.push(0x03); tbs.push(0x02);
        // Issuer: 30 00
        tbs.push(0x30); tbs.push(0x00);
        // Validity: 30 1E 17 0D 260101000000Z 17 0D 270101000000Z
        tbs.push(0x30); tbs.push(0x1E);
        tbs.push(0x17); tbs.push(0x0D);
        let time1 = "260101000000Z";
        for i in 13 { tbs.push(time1[i]); }
        tbs.push(0x17); tbs.push(0x0D);
        let time2 = "270101000000Z";
        for i in 13 { tbs.push(time2[i]); }
        // Subject: 30 00
        tbs.push(0x30); tbs.push(0x00);
        // SPKI: 30 13 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 05 00 01 02 03 04
        tbs.push(0x30); tbs.push(0x13);
        tbs.push(0x30); tbs.push(0x0A); tbs.push(0x06); tbs.push(0x08);
        tbs.push(0x2A); tbs.push(0x86); tbs.push(0x48); tbs.push(0xCE); tbs.push(0x3D); tbs.push(0x04); tbs.push(0x03); tbs.push(0x02);
        tbs.push(0x03); tbs.push(0x05); tbs.push(0x00); tbs.push(0x01); tbs.push(0x02); tbs.push(0x03); tbs.push(0x04);

        // Wrap into Certificate sequence
        var cert: u8[>..] = [];
        // Sig Alg
        var sig_alg_and_sig: u8[>..] = [];
        sig_alg_and_sig.push(0x30); sig_alg_and_sig.push(0x0A); sig_alg_and_sig.push(0x06); sig_alg_and_sig.push(0x08);
        sig_alg_and_sig.push(0x2A); sig_alg_and_sig.push(0x86); sig_alg_and_sig.push(0x48); sig_alg_and_sig.push(0xCE); sig_alg_and_sig.push(0x3D); sig_alg_and_sig.push(0x04); sig_alg_and_sig.push(0x03); sig_alg_and_sig.push(0x02);
        sig_alg_and_sig.push(0x03); sig_alg_and_sig.push(0x05); sig_alg_and_sig.push(0x00); sig_alg_and_sig.push(0xAA); sig_alg_and_sig.push(0xBB); sig_alg_and_sig.push(0xCC); sig_alg_and_sig.push(0xDD);

        let total_tbs_len = tbs.len;
        let outer_len = 2 + total_tbs_len + sig_alg_and_sig.len;

        cert.push(0x30);
        if outer_len < 128 {
            cert.push(outer_len as u8);
        } else {
            cert.push(0x81);
            cert.push(outer_len as u8);
        }

        // TBS sequence header
        cert.push(0x30);
        if total_tbs_len < 128 {
            cert.push(total_tbs_len as u8);
        } else {
            cert.push(0x81);
            cert.push(total_tbs_len as u8);
        }
        cert.append(tbs[..]);
        cert.append(sig_alg_and_sig[..]);

        var parsed = wing::ParsedCert { .. };
        let ok = wing::parse_x509_certificate(cert[..], parsed);
        sub.assert_true(ok, "parse_x509_certificate MUST succeed on standard X.509 v3 certificate with explicit [0] version tag");
    };
}

// ----------------------------------------------------------------------------
// 4. Set-Cookie Name Length Exceeding 256 Bytes Buffer Bounds (cookie/parser.goose)
// ----------------------------------------------------------------------------
fn test_cookie_parser_name_length_bounds(t: core::T&) {
    t.run("Set-Cookie with name > 256 bytes must be rejected safely without aborting") { sub =>
        // Construct 300-byte name and small value (sum = 305 <= 4096)
        var raw_hdr: u8[..512] = [];
        for i in 300 { raw_hdr.push('x' as u8); }
        raw_hdr.append("=val");

        let c, cause, ok = wing::parse_canonical_set_cookie(raw_hdr[..], "example.com", "/", 1000000);
        sub.assert_false(ok, "parse_canonical_set_cookie MUST reject cookie name > 256 bytes without panicking");
    };
}

// ----------------------------------------------------------------------------
// 5. Set-Cookie Domain/Path Attribute Exceeding 256 Bytes (cookie/parser.goose)
// ----------------------------------------------------------------------------
fn test_cookie_parser_domain_path_attr_bounds(t: core::T&) {
    t.run("Set-Cookie with Domain attribute > 256 bytes must not abort") { sub =>
        var raw_hdr: u8[..600] = "sess=123; Domain=";
        for i in 300 { raw_hdr.push('a' as u8); }
        raw_hdr.append(".com; Path=/");

        let c, cause, ok = wing::parse_canonical_set_cookie(raw_hdr[..], "example.com", "/", 1000000);
        // Domain attribute is ignored due to oversized length, but process must not crash
        sub.assert_true(true, "Oversized domain attribute did not cause a process abort");
    };
}

// ----------------------------------------------------------------------------
// 6. CSRF FetchContext Method and Origin Bounds (security/csrf.goose)
// ----------------------------------------------------------------------------
fn test_csrf_fetch_context_method_and_headers(t: core::T&) {
    t.run("extract_fetch_context must correctly set method and safely handle duplicate Origin") { sub =>
        var req = wing::Request { .. };
        req.method.clear();
        req.method.append("POST");
        req.headers.push(wing::make_header("Origin", "https://app1.example.com"));
        req.headers.push(wing::make_header("Origin", "https://app2.example.com"));

        let ctx = wing::extract_fetch_context(req, "example.com");

        sub.assert_eq(ctx.method[..], "POST", "ctx.method must be exactly 'POST', not 'GETPOST'");
        sub.assert_eq(ctx.origin[..], "https://app1.example.com", "ctx.origin must retain only the first valid Origin and not concatenate");
    };
}

// ----------------------------------------------------------------------------
// 7. gRPC-Web Trailers CRLF Injection and Buffer Bounds (grpc/framing.goose)
// ----------------------------------------------------------------------------
fn test_grpc_web_trailers_percent_encoding(t: core::T&) {
    t.run("encode_grpc_web_trailers must percent-encode CRLF in message") { sub =>
        let malicious_msg = "Error occurred\r\ninjected-header: bad";
        var out_wire: u8[>..] = [];

        wing::encode_grpc_web_trailers(wing::GrpcStatusCode.Internal, malicious_msg, out_wire);

        // Body begins at offset 5 (1 byte flag + 4 bytes length)
        sub.assert_true(out_wire.len >= 5, "gRPC-Web trailers frame must have header");
        let body = out_wire[5..];

        // Ensure there is no bare "\r\ninjected-header" in the decoded trailer lines
        // A raw trailer line ending with injected-header would mean CRLF was unescaped
        sub.assert_false(core::contains(body, "\r\ninjected-header:"), "encode_grpc_web_trailers must not allow unescaped CRLF trailer injection");
    };
}

// ----------------------------------------------------------------------------
// 8. Rate Limiter KeyedGcraSlot Oversized Key Bounds (security/rate_limiter.goose)
// ----------------------------------------------------------------------------
fn test_rate_limiter_oversized_key(t: core::T&) {
    t.run("check_rate_limit with key > 64 bytes must not crash with capacity panic") { sub =>
        let quota = wing::new_gcra_quota(10, core::Duration { nanos: 1000000000 }, 5);
        var limiter = wing::new_sharded_limiter(quota);

        var long_key: u8[..200] = [];
        for i in 120 { long_key.push('K' as u8); }

        let decision = wing::check_rate_limit(limiter, long_key[..], 1, 1000);
        sub.assert_true(wing::is_allowed(decision), "check_rate_limit with 120-byte key must succeed without panicking");
    };
}

// ----------------------------------------------------------------------------
// 9. CORS Policy Oversized Origin Pattern Bounds (security/cors.goose)
// ----------------------------------------------------------------------------
fn test_cors_oversized_pattern_bounds(t: core::T&) {
    t.run("add_allowed_origin with pattern > 128 bytes must return false safely") { sub =>
        var policy = wing::new_cors_policy();
        var long_pattern: u8[..200] = "https://";
        for i in 150 { long_pattern.push('z' as u8); }
        long_pattern.append(".example.com");

        let ok = wing::add_allowed_origin(policy, long_pattern[..]);
        sub.assert_false(ok, "add_allowed_origin MUST reject pattern > 128 bytes instead of aborting");
    };
}

// ----------------------------------------------------------------------------
// 10. Cross-Origin Isolation Oversized Origin Bounds (security/cross_origin_isolation.goose)
// ----------------------------------------------------------------------------
fn test_cross_origin_isolation_oversized_origin(t: core::T&) {
    t.run("update_isolation_context with origin > 128 bytes must not abort") { sub =>
        var ctx = wing::CrossOriginIsolationContext { .. };
        var long_origin: u8[..256] = "https://";
        for i in 150 { long_origin.push('a' as u8); }
        long_origin.append(".example.org");

        wing::update_isolation_context(ctx, "same-origin", "require-corp", long_origin[..]);
        sub.assert_true(true, "update_isolation_context handled oversized origin without aborting");
    };
}

// ----------------------------------------------------------------------------
// 11. Netscape Cookies.txt Oversized Fields Defense (cookie/store.goose)
// ----------------------------------------------------------------------------
fn test_netscape_cookie_oversized_fields(t: core::T&) {
    t.run("try_parse_netscape_cookie_line with oversized name must return false safely") { sub =>
        var line: u8[..600] = "example.com\tTRUE\t/\tFALSE\t2000000000\t";
        for i in 300 { line.push('n' as u8); }
        line.append("\tvalue");

        var c = wing::CanonicalCookie { .. };
        let ok = wing::try_parse_netscape_cookie_line(line[..], c);
        sub.assert_false(ok, "try_parse_netscape_cookie_line MUST reject name > 256 bytes without panicking");
    };
}

// ----------------------------------------------------------------------------
// 12. JWKS Oversized Kid and JSON Member Bounds (auth/jwks.goose)
// ----------------------------------------------------------------------------
fn test_jwks_oversized_kid_bounds(t: core::T&) {
    t.run("add_ed25519_key with kid > 64 bytes must return false safely") { sub =>
        var jwks = wing::new_jwks();
        var long_kid: u8[..128] = [];
        for i in 80 { long_kid.push('k' as u8); }
        var pub_key: u8[32] = [0x55; 32];

        let ok = wing::add_ed25519_key(jwks, long_kid[..], pub_key);
        sub.assert_false(ok, "add_ed25519_key MUST reject kid > 64 bytes without panicking");
    };
}

// ----------------------------------------------------------------------------
// 13. SigV4 Long Secret Key Derivation (auth/sigv4.goose)
// ----------------------------------------------------------------------------
fn test_sigv4_long_secret_key(t: core::T&) {
    t.run("derive_aws_signing_key with secret_key > 136 bytes must not abort") { sub =>
        var long_secret: u8[..256] = [];
        for i in 180 { long_secret.push('s' as u8); }

        let k = wing::derive_aws_signing_key(long_secret[..], "20261027", "us-east-1", "s3");
        sub.assert_true(true, "derive_aws_signing_key with 180-byte secret completed without panicking");
    };
}

fn main() {
    let _ = wing::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = core::new_runner("RED Suite Phase 11: Security & Protocol Flaws", core::Verbosity.Verbose);

    core::run_case(runner, "1. SignedJar HMAC Cookie Name Swapping (security/crypto_jar.goose)", test_signed_jar_cookie_name_swapping);
    core::run_case(runner, "2. RFC 9000 §4.5 QUIC FINAL_SIZE_ERROR on FIN < buffered data", test_quic_final_size_error_less_than_buffered);
    core::run_case(runner, "3. X.509 v3 Explicit Version Tag Parsing (tls/x509.goose)", test_x509_v3_version_parsing);
    core::run_case(runner, "4. Set-Cookie Name Length Exceeding 256 Bytes (cookie/parser.goose)", test_cookie_parser_name_length_bounds);
    core::run_case(runner, "5. Set-Cookie Domain/Path Attribute Exceeding 256 Bytes (cookie/parser.goose)", test_cookie_parser_domain_path_attr_bounds);
    core::run_case(runner, "6. CSRF FetchContext Method and Origin Bounds (security/csrf.goose)", test_csrf_fetch_context_method_and_headers);
    core::run_case(runner, "7. gRPC-Web Trailers CRLF Injection & Bounds (grpc/framing.goose)", test_grpc_web_trailers_percent_encoding);
    core::run_case(runner, "8. Rate Limiter KeyedGcraSlot Oversized Key Bounds (security/rate_limiter.goose)", test_rate_limiter_oversized_key);
    core::run_case(runner, "9. CORS Policy Oversized Origin Pattern Bounds (security/cors.goose)", test_cors_oversized_pattern_bounds);
    core::run_case(runner, "10. Cross-Origin Isolation Oversized Origin (security/cross_origin_isolation.goose)", test_cross_origin_isolation_oversized_origin);
    core::run_case(runner, "11. Netscape Cookies.txt Oversized Fields Defense (cookie/store.goose)", test_netscape_cookie_oversized_fields);
    core::run_case(runner, "12. JWKS Oversized Kid and JSON Member Bounds (auth/jwks.goose)", test_jwks_oversized_kid_bounds);
    core::run_case(runner, "13. SigV4 Long Secret Key Derivation (auth/sigv4.goose)", test_sigv4_long_secret_key);

    let ok = core::finish(runner);
    assert(ok);
}
