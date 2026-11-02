// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_query_token_slicing.goose
// Verification of Zero-Copy Query Token Slicing and SWAR 64-bit wire parsing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";

fn main() {
    // 1. Basic zero-copy token slicing
    let wire = "?user=alice&role=admin";
    let q1 = core::parse_query_params(wire);
    assert(q1.tokens.len == 2);
    assert(!q1.overflow);

    let k0 = core::query_token_key(q1.tokens[0], q1.wire);
    let v0 = core::query_token_val(q1.tokens[0], q1.wire);
    assert(k0 == "user");
    assert(v0 == "alice");

    let k1 = core::query_token_key(q1.tokens[1], q1.wire);
    let v1 = core::query_token_val(q1.tokens[1], q1.wire);
    assert(k1 == "role");
    assert(v1 == "admin");
    print("BASIC_TOKENS: OK");

    // 2. SWAR 64-bit scanning across multi-word boundaries
    let long_wire = "?alpha_long_parameter_key=first_long_parameter_value&beta_second_parameter=second_value";
    let q2 = core::parse_query_params(long_wire);
    assert(q2.tokens.len == 2);
    assert(core::has_query_param(q2, "alpha_long_parameter_key"));
    assert(core::has_query_param(q2, "beta_second_parameter"));
    assert(core::get_query_param(q2, "alpha_long_parameter_key") == "first_long_parameter_value");
    assert(core::get_query_param(q2, "beta_second_parameter") == "second_value");
    print("SWAR_SCANNING: OK");

    // 3. Valueless parameter flags
    let flag_wire = "?debug&empty=&mode=fast";
    let q3 = core::parse_query_params(flag_wire);
    assert(q3.tokens.len == 3);
    assert(core::query_token_is_valueless(q3.tokens[0]));
    assert(core::query_token_key(q3.tokens[0], q3.wire) == "debug");
    assert(core::query_token_val(q3.tokens[0], q3.wire) == "");

    assert(!core::query_token_is_valueless(q3.tokens[1]));
    assert(core::query_token_key(q3.tokens[1], q3.wire) == "empty");
    assert(core::query_token_val(q3.tokens[1], q3.wire) == "");

    assert(!core::query_token_is_valueless(q3.tokens[2]));
    assert(core::query_token_key(q3.tokens[2], q3.wire) == "mode");
    assert(core::query_token_val(q3.tokens[2], q3.wire) == "fast");
    print("VALUELESS_FLAGS: OK");

    // 4. Raw wire slice vs decoded parameter value
    let enc_wire = "?greeting=hello%20world%21&plain=test";
    let q4 = core::parse_query_params(enc_wire);
    assert(core::query_token_has_escape(q4.tokens[0]));
    assert(!core::query_token_has_escape(q4.tokens[1]));

    // Vulkan-like raw wire return: no implicit heap/stack allocation
    let raw_v = core::get_query_param(q4, "greeting");
    assert(raw_v == "hello%20world%21");

    // Explicit decoding helper
    var dec_buf: u8[..64] = [];
    let dec_ok = core::get_query_param_decoded(q4, "greeting", dec_buf);
    assert(dec_ok);
    assert(dec_buf[..] == "hello world!");
    print("DECODED_HELPER: OK");

    // 5. CVE-2021-31525 Semicolon preserved as literal content
    let semi_wire = "?tag=a;b;c&id=42";
    let q5 = core::parse_query_params(semi_wire);
    assert(q5.tokens.len == 2);
    assert(core::get_query_param(q5, "tag") == "a;b;c");
    assert(core::get_query_param(q5, "id") == "42");
    print("SEMICOLON_DEFENSE: OK");

    // 6. Fragment truncation
    let frag_wire = "?status=active#ignored_section";
    let q6 = core::parse_query_params(frag_wire);
    assert(q6.tokens.len == 1);
    assert(core::get_query_param(q6, "status") == "active");
    print("FRAGMENT_TRUNCATION: OK");

    print("ALL_QUERY_TOKEN_LIT_TESTS_PASSED");
}

// CHECK: BASIC_TOKENS: OK
// CHECK-NEXT: SWAR_SCANNING: OK
// CHECK-NEXT: VALUELESS_FLAGS: OK
// CHECK-NEXT: DECODED_HELPER: OK
// CHECK-NEXT: SEMICOLON_DEFENSE: OK
// CHECK-NEXT: FRAGMENT_TRUNCATION: OK
// CHECK-NEXT: ALL_QUERY_TOKEN_LIT_TESTS_PASSED
