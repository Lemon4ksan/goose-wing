// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_security_bug_hunter.goose
// Regression tests for security audit findings:
// 1. CryptoJar bounded-buffer truncation and fail-closed timestamp validation (GOOSE-BUG-1, GOOSE-BUG-2)
// 2. CSRF path prefix exemption matching (GOOSE-BUG-6)
// 3. GCRA rate limiter shard slot allocation priority vs premature eviction (GOOSE-BUG-7)
// 4. PrivacyPass duplicate auth-param rejection (RFC 9577 §2.1, GOOSE-BUG-1)
// 5. Missing security APIs integration (validate_cors_policy, apply_strict_cross_origin_isolation, pop_private_token)
//
// RUN: goose --cc gcc %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_cryptojar_bounded_buffer_truncation() {
    var store = wing::KeyStore { .. };
    var raw_key: u8[32] = [0x55; 32];
    let slot = core::new_key_slot(1, raw_key[..], 1700000000);
    assert(wing::add_key(store, slot));

    let pjar_xchacha = wing::new_private_jar(store, false);
    let pjar_aes = wing::new_private_jar(store, true);
    let sjar = wing::new_signed_jar(store);

    // 1. XChaCha20 seal with undersized out buffer must fail, not silently truncate
    var small_buf_x: u8[..40] = []; // K_OVERHEAD_XCHACHA20 is 53
    let ok_x = wing::private_jar_seal_binary(pjar_xchacha, "sid", "secret_payload", 1700000000, 12345, small_buf_x);
    assert(!ok_x);

    // 2. HKDF-AES-GCM seal with undersized out buffer must fail, not silently truncate
    var small_buf_aes: u8[..50] = []; // K_OVERHEAD_HKDF_AES_GCM is 65
    let ok_aes = wing::private_jar_seal_binary(pjar_aes, "sid", "secret_payload", 1700000000, 12345, small_buf_aes);
    assert(!ok_aes);

    // 3. SignedJar seal with undersized out buffer must fail, not silently truncate
    var small_buf_sign: u8[..30] = []; // K_OVERHEAD_HMAC_SHA256 is 45
    let ok_sign = wing::signed_jar_seal_binary(sjar, "sid", "secret_payload", 1700000000, small_buf_sign);
    assert(!ok_sign);

    // 4. SignedJar open with undersized out_payload buffer must fail, not silently truncate
    var valid_signed_wire: u8[..128] = [];
    assert(wing::signed_jar_seal_binary(sjar, "sid", "longer_payload_string", 1700000000, valid_signed_wire));
    var tiny_payload_out: u8[..8] = []; // "longer_payload_string" is 21 bytes
    let ok_open = wing::signed_jar_open_binary(sjar, "sid", valid_signed_wire[..], 1700000001, tiny_payload_out);
    assert(!ok_open);

    print("CRYPTOJAR_BOUNDS_CHECK: OK");
}

fn test_cryptojar_timestamp_fail_closed() {
    var store = wing::KeyStore { .. };
    // Fail-closed on zero or negative now_sec
    assert(!wing::is_cookie_timestamp_valid(store, 1700000000, 0));
    assert(!wing::is_cookie_timestamp_valid(store, 1700000000, -100));
    assert(wing::is_cookie_timestamp_valid(store, 1700000000, 1700000010));

    print("CRYPTOJAR_TIMESTAMP_FAIL_CLOSED: OK");
}

fn test_csrf_path_prefix_exemption() {
    var guard_cfg = wing::CrossOriginGuard { .. };
    assert(wing::add_exempt_path(guard_cfg, "/api/webhook"));
    assert(wing::add_exempt_path(guard_cfg, "/public/"));

    var ctx1 = wing::FetchContext {
        site:           wing::SecFetchSite.CrossSite,
        method_is_safe: false,
        ..
    };
    // 1. Exact match
    ctx1.path.try_set("/api/webhook");
    let d1 = wing::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(wing::is_allowed(d1));

    // 2. Subpath under /api/webhook/
    ctx1.path.try_set("/api/webhook/stripe");
    let d2 = wing::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(wing::is_allowed(d2));

    // 3. Subpath under /public/
    ctx1.path.try_set("/public/bundle.js");
    let d3 = wing::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(wing::is_allowed(d3));

    // 4. Must NOT match sibling prefix /api/webhook_attack
    ctx1.path.try_set("/api/webhook_attack");
    let d4 = wing::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(!wing::is_allowed(d4));

    print("CSRF_PATH_PREFIX_EXEMPTION: OK");
}

fn test_gcra_shard_slot_allocation_priority() {
    let quota = wing::new_gcra_quota(10, core::seconds(1), 5);
    var limiter = wing::new_sharded_limiter(quota);

    // Request from client A at t = 1000
    let d_a1 = wing::check_rate_limit(limiter, "client_a", 1, 1000);
    assert(wing::is_allowed(d_a1));

    // Request from client B at t = 2000000000 (after client A's TAT has expired)
    // Limiter shard has 16 capacity and only 1 slot used!
    // It must allocate a NEW slot for client B, preserving client A's slot in the table.
    let d_b1 = wing::check_rate_limit(limiter, "client_b", 1, 2000000000);
    assert(wing::is_allowed(d_b1));

    // Find shard index for client_a
    let shard_idx = (core::fnv1a_64("client_a") & 0xFF) as i64;
    // Both client_a and client_b should have active slots if they hashed to the same shard,
    // or at least client_a's slot was not overwritten if slots.len < slots.cap.
    if (core::fnv1a_64("client_b") & 0xFF) as i64 == shard_idx {
        assert(limiter.shards[shard_idx].slots.len == 2);
    }

    print("GCRA_SLOT_PRIORITY: OK");
}

fn test_privacypass_duplicate_params() {
    var out_chal = wing::TokenChallenge { .. };
    var out_key: u8[..128] = [];
    var max_age: i64       = 0;

    // RFC 9577 §2.1: Duplicate challenge param MUST be rejected
    let ok_dup_chal = wing::parse_private_token_challenge(
        "PrivateToken challenge=\"AQIDBA\", challenge=\"BQYHCA\"",
        out_chal,
        out_key,
        max_age,
    );
    assert(!ok_dup_chal);

    // RFC 9577 §2.1: Duplicate token-key param MUST be rejected
    let ok_dup_key = wing::parse_private_token_challenge(
        "PrivateToken challenge=\"AQIDBA\", token-key=\"a2V5MQ\", token-key=\"a2V5Mg\"",
        out_chal,
        out_key,
        max_age,
    );
    assert(!ok_dup_key);

    // RFC 9577 §2.1: Duplicate max-age param MUST be rejected
    let ok_dup_age = wing::parse_private_token_challenge(
        "PrivateToken challenge=\"AQIDBA\", max-age=60, max-age=120",
        out_chal,
        out_key,
        max_age,
    );
    assert(!ok_dup_age);

    print("PRIVACYPASS_DUPLICATES_REJECTED: OK");
}

fn test_missing_security_apis() {
    // 1. validate_cors_policy
    var cors_valid = wing::CorsPolicy { .. };
    assert(wing::validate_cors_policy(cors_valid));

    var cors_invalid = wing::CorsPolicy { allow_credentials: true, .. };
    assert(wing::add_allowed_origin(cors_invalid, "https://example.com"));
    assert(wing::add_allowed_origin(cors_invalid, "*"));
    assert(!wing::validate_cors_policy(cors_invalid));

    // 2. apply_strict_cross_origin_isolation
    var res = wing::Response { .. };
    wing::apply_strict_cross_origin_isolation(res);
    assert(res.header("Cross-Origin-Opener-Policy") == "same-origin");
    assert(res.header("Cross-Origin-Embedder-Policy") == "require-corp");
    assert(res.header("Cross-Origin-Resource-Policy") == "same-origin");

    // 3. pop_private_token
    var cache = wing::PrivateTokenCache { .. };
    var chal = wing::TokenChallenge { issuer_name: "test_issuer", .. };
    var tok = wing::Token { .. };
    let raw_token = "blind_rsa_raw_token";
    assert(wing::put_private_token(cache, chal, tok, raw_token, 300, 1000));

    let digest = wing::compute_challenge_digest(chal);
    var popped_raw: u8[..512] = [];
    assert(wing::pop_private_token(cache, digest, 1010, popped_raw));
    assert(popped_raw[..] == "blind_rsa_raw_token");

    // Single-use: second pop must fail
    var popped_second: u8[..512] = [];
    assert(!wing::pop_private_token(cache, digest, 1011, popped_second));

    print("MISSING_SECURITY_APIS: OK");
}

fn test_cryptojar_private_open_bounded_buffer() {
    var store = wing::KeyStore { .. };
    var raw_key: u8[32] = [0x42; 32];
    let slot = core::new_key_slot(1, raw_key[..], 1700000000);
    assert(wing::add_key(store, slot));

    let pjar_xchacha = wing::new_private_jar(store, false);
    let pjar_aes = wing::new_private_jar(store, true);

    var valid_x_wire: u8[..256] = [];
    assert(wing::private_jar_seal_binary(pjar_xchacha, "session", "my_secret_32_byte_payload_string!", 1700000000, 999, valid_x_wire));

    var tiny_out_x: u8[..8] = [];
    let ok_open_x = wing::private_jar_open_binary(pjar_xchacha, "session", valid_x_wire[..], 1700000001, tiny_out_x);
    assert(!ok_open_x);

    var valid_aes_wire: u8[..256] = [];
    assert(wing::private_jar_seal_binary(pjar_aes, "session", "my_secret_32_byte_payload_string!", 1700000000, 888, valid_aes_wire));

    var tiny_out_aes: u8[..8] = [];
    let ok_open_aes = wing::private_jar_open_binary(pjar_aes, "session", valid_aes_wire[..], 1700000001, tiny_out_aes);
    assert(!ok_open_aes);

    print("CRYPTOJAR_PRIVATE_OPEN_BOUNDS: OK");
}

fn test_privacypass_cache_eviction_perpetual_tokens() {
    var cache = wing::PrivateTokenCache { .. };
    var tok = wing::Token { .. };

    var chal0 = wing::TokenChallenge { issuer_name: "issuer_perpetual", .. };
    assert(wing::put_private_token(cache, chal0, tok, "token_perpetual", 0, 1000));

    for i in 1..16 {
        var chali = wing::TokenChallenge { issuer_name: "issuer_expiring", .. };
        chali.redemption_context.push(i as u8);
        let ttl = i * 10;
        assert(wing::put_private_token(cache, chali, tok, "token_expiring", ttl, 1000));
    }
    assert(cache.entries.len == 16);

    var chal17 = wing::TokenChallenge { issuer_name: "issuer_new", .. };
    assert(wing::put_private_token(cache, chal17, tok, "token_new", 500, 1005));

    var out_tok = wing::Token { .. };
    var out_raw: u8[..512] = [];
    assert(wing::get_private_token(cache, chal0, 1006, out_tok, out_raw));
    assert(out_raw[..] == "token_perpetual");

    print("PRIVACYPASS_PERPETUAL_TOKEN_EVICTION: OK");
}

fn test_rate_limiter_probabilistic_saturation() {
    let quota = wing::new_gcra_quota(1, core::seconds(1), 0);
    var pgcra = wing::new_probabilistic_gcra(quota, 100);
    pgcra.cell.tat_ns = 5000000000;

    pgcra.rng_state = 1;
    let dec = wing::check_rate_limit(pgcra, 1, 1000000000);
    assert(!wing::is_allowed(dec));

    print("PROBABILISTIC_GCRA_SATURATION: OK");
}

fn test_cors_empty_origin_rejected() {
    var policy = wing::CorsPolicy { .. };
    assert(!wing::add_allowed_origin(policy, ""));
    assert(wing::add_allowed_origin(policy, "https://example.com"));

    print("CORS_EMPTY_ORIGIN_REJECTED: OK");
}

fn main() {
    test_cryptojar_bounded_buffer_truncation();
    test_cryptojar_timestamp_fail_closed();
    test_csrf_path_prefix_exemption();
    test_gcra_shard_slot_allocation_priority();
    test_privacypass_duplicate_params();
    test_missing_security_apis();
    test_cryptojar_private_open_bounded_buffer();
    test_privacypass_cache_eviction_perpetual_tokens();
    test_rate_limiter_probabilistic_saturation();
    test_cors_empty_origin_rejected();

    print("ALL_SECURITY_BUG_HUNTER_TESTS_PASSED");
}

// CHECK: CRYPTOJAR_BOUNDS_CHECK: OK
// CHECK-NEXT: CRYPTOJAR_TIMESTAMP_FAIL_CLOSED: OK
// CHECK-NEXT: CSRF_PATH_PREFIX_EXEMPTION: OK
// CHECK-NEXT: GCRA_SLOT_PRIORITY: OK
// CHECK-NEXT: PRIVACYPASS_DUPLICATES_REJECTED: OK
// CHECK-NEXT: MISSING_SECURITY_APIS: OK
// CHECK-NEXT: CRYPTOJAR_PRIVATE_OPEN_BOUNDS: OK
// CHECK-NEXT: PRIVACYPASS_PERPETUAL_TOKEN_EVICTION: OK
// CHECK-NEXT: PROBABILISTIC_GCRA_SATURATION: OK
// CHECK-NEXT: CORS_EMPTY_ORIGIN_REJECTED: OK
// CHECK-NEXT: ALL_SECURITY_BUG_HUNTER_TESTS_PASSED
