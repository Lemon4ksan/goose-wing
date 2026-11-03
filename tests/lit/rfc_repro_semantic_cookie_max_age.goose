// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_semantic_cookie_max_age.goose
// Verification of RFC 6265 Section 5.2.2 Max-Age attribute handling.
// RFC 6265 Section 5.2.2: The Max-Age Attribute - If delta-seconds is less than or equal to zero (0), let expiry-time be the earliest representable date and time.
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    let now_us: i64 = 1700000000000000;

    var c_zero = wing::new_canonical_cookie("session", "abc");
    c_zero.with_max_age_seconds(0, now_us);
    print("MAX_AGE_ZERO: ", c_zero.expires_utc, "\n");

    var c_neg = wing::new_canonical_cookie("session", "abc");
    c_neg.with_max_age_seconds(-60, now_us);
    print("MAX_AGE_NEG: ", c_neg.expires_utc, "\n");

    var c_pos = wing::new_canonical_cookie("session", "abc");
    c_pos.with_max_age_seconds(3600, now_us);
    print("MAX_AGE_POS_DELTA: ", c_pos.expires_utc - now_us, "\n");
}

// CHECK: MAX_AGE_ZERO: 0
// CHECK: MAX_AGE_NEG: 0
// CHECK: MAX_AGE_POS_DELTA: 3600000000
