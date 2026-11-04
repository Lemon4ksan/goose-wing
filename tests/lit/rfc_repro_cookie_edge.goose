// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_cookie_edge.goose
// Verification of Cookie edge invariants, bounds, enum fallback, and arithmetic safety.
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    let now_us: i64 = 1700000000000000;

    // 1. SameSite and Priority enum fallback (Rule 15: Unknown on invalid values)
    let ss_invalid = wing::parse_cookie_same_site("invalid_samesite");
    print("SS_INVALID: ", ss_invalid == wing::CookieSameSite.Unknown, "\n");
    let prio_invalid = wing::parse_cookie_priority("invalid_priority");
    print("PRIO_INVALID: ", prio_invalid == wing::CookiePriority.Unknown, "\n");

    // 2. Capacity safety in with_domain, with_path, with_partition_key
    var c = wing::new_canonical_cookie("sid", "val");
    var huge_path: u8[..300] = [];
    for i in 280 { huge_path.push('x'); }
    c.with_path(huge_path[..]);
    print("HUGE_PATH_SAFE: ", c.path[..] == "/", "\n");

    // 3. Calendar date validation: year > 9999 rejected
    let _, date_valid_ok = wing::parse_cookie_date_us("Wed, 09 Jun 2021 10:18:14 GMT");
    print("DATE_VALID: ", date_valid_ok, "\n");
    let _, date_huge_yr_ok = wing::parse_cookie_date_us("Wed, 09 Jun 99999 10:18:14 GMT");
    print("DATE_HUGE_YR: ", date_huge_yr_ok, "\n");

    // 4. URL parsing bounds safety on long path
    let url_long = wing::parse_canonical_cookie_url("https://example.com/api/test");
    print("URL_HOST: ", url_long.host[..], "\n");
    print("URL_PATH: ", url_long.path[..], "\n");

    // 5. Saturating max-age calculation
    var c_max = wing::new_canonical_cookie("tok", "123");
    c_max.with_max_age_seconds(999999999, now_us);
    print("CAPPED_PERSISTENT: ", c_max.persistent, "\n");
    print("EXPIRES_GREATER: ", c_max.expires_utc > now_us, "\n");
}

// CHECK: SS_INVALID: true
// CHECK: PRIO_INVALID: true
// CHECK: HUGE_PATH_SAFE: true
// CHECK: DATE_VALID: true
// CHECK: DATE_HUGE_YR: false
// CHECK: URL_HOST: example.com
// CHECK: URL_PATH: /api/test
// CHECK: CAPPED_PERSISTENT: true
// CHECK: EXPIRES_GREATER: true
