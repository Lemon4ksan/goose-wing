// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for Vulkan-style zero-allocation HeaderMap next_header_value cursor iteration:
// 1. Single well-known and custom header retrieval.
// 2. Multi-value repeated header chain iteration (Set-Cookie, Via, X-Custom).
// 3. Non-existent header lookup returns false and sets cursor = -1.
// 4. Empty-value header correctly returns ok=true with empty slice.
// 5. Terminal contract: exhausted cursor repeatedly returns false.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_single_header_cursor(t: lit::T&) {
    t.run("Single Well-Known Header") { sub =>
        var map = wing::HeaderMap {};
        let ok1 = map.append_header("Host", "example.com");
        sub.assert_true(ok1, "append Host succeeds");

        var cursor: i64 = 0;
        let val, ok = wing::next_header_value(map, "", "Host", cursor);
        sub.assert_true(ok, "first Host found");
        sub.assert_eq(val, "example.com", "value matches");
        sub.assert_eq(cursor, -1, "cursor terminates at -1 for single entry");

        let val_end, ok_end = wing::next_header_value(map, "", "Host", cursor);
        sub.assert_false(ok_end, "terminal call returns false");
        sub.assert_eq(val_end, "", "exhausted value is empty");
        sub.assert_eq(cursor, -1, "cursor remains -1");
    };

    t.run("Single Custom Header") { sub =>
        var map = wing::HeaderMap {};
        let ok1 = map.append_header("X-Request-Id", "req-12345");
        sub.assert_true(ok1, "append custom succeeds");

        var cursor: i64 = 0;
        let val, ok = wing::next_header_value(map, "", "X-Request-Id", cursor);
        sub.assert_true(ok, "custom header found");
        sub.assert_eq(val, "req-12345", "value matches");
        sub.assert_eq(cursor, -1, "cursor terminates at -1");
    };

    t.run("Non-Existent Header") { sub =>
        var map = wing::HeaderMap {};
        map.append_header("Host", "example.com");

        var cursor: i64 = 0;
        let val, ok = wing::next_header_value(map, "", "Authorization", cursor);
        sub.assert_false(ok, "non-existent header returns false");
        sub.assert_eq(val, "", "empty return");
        sub.assert_eq(cursor, -1, "cursor set to -1");

        // Custom non-existent
        var cursor2: i64 = 0;
        let val2, ok2 = wing::next_header_value(map, "", "X-Missing", cursor2);
        sub.assert_false(ok2, "non-existent custom returns false");
        sub.assert_eq(val2, "", "empty return");
        sub.assert_eq(cursor2, -1, "cursor set to -1");
    };
}

fn test_multi_value_header_cursor(t: lit::T&) {
    t.run("Multi-Value Well-Known Set-Cookie Chain") { sub =>
        var map = wing::HeaderMap {};
        map.append_header("Host", "example.com");
        map.append_header("Set-Cookie", "session=abc; Path=/; Secure");
        map.append_header("Content-Type", "text/html");
        map.append_header("Set-Cookie", "theme=dark; Path=/");
        map.append_header("Set-Cookie", "experiment=variant_b; Path=/");

        var cursor: i64 = 0;

        // 1st Set-Cookie
        let val1, ok1 = wing::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_true(ok1, "1st Set-Cookie found");
        sub.assert_eq(val1, "session=abc; Path=/; Secure");
        sub.assert_true(cursor >= 0, "cursor advances to next index");

        // 2nd Set-Cookie
        let val2, ok2 = wing::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_true(ok2, "2nd Set-Cookie found");
        sub.assert_eq(val2, "theme=dark; Path=/");
        sub.assert_true(cursor >= 0, "cursor advances to 3rd index");

        // 3rd Set-Cookie
        let val3, ok3 = wing::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_true(ok3, "3rd Set-Cookie found");
        sub.assert_eq(val3, "experiment=variant_b; Path=/");
        sub.assert_eq(cursor, -1, "cursor terminates at -1");

        // Terminal
        let val4, ok4 = wing::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_false(ok4, "terminal return is false");
        sub.assert_eq(cursor, -1, "cursor remains -1");
    };

    t.run("Multi-Value Custom Header Chain") { sub =>
        var map = wing::HeaderMap {};
        map.append_header("X-Forwarded-For", "192.168.1.1");
        map.append_header("Server", "goose-wing");
        map.append_header("X-Forwarded-For", "10.0.0.1");
        map.append_header("X-Forwarded-For", "172.16.0.1");

        var cursor: i64 = 0;

        let val1, ok1 = wing::next_header_value(map, "", "x-forwarded-for", cursor);
        sub.assert_true(ok1, "case-insensitive 1st found");
        sub.assert_eq(val1, "192.168.1.1");

        let val2, ok2 = wing::next_header_value(map, "", "X-FORWARDED-FOR", cursor);
        sub.assert_true(ok2, "case-insensitive 2nd found");
        sub.assert_eq(val2, "10.0.0.1");

        let val3, ok3 = wing::next_header_value(map, "", "X-Forwarded-For", cursor);
        sub.assert_true(ok3, "case-insensitive 3rd found");
        sub.assert_eq(val3, "172.16.0.1");
        sub.assert_eq(cursor, -1, "terminal cursor -1");

        let _, ok4 = wing::next_header_value(map, "", "X-Forwarded-For", cursor);
        sub.assert_false(ok4, "terminal exhausted");
    };

    t.run("Empty Header Value") { sub =>
        var map = wing::HeaderMap {};
        map.append_header("X-Empty-Flag", "");

        var cursor: i64 = 0;
        let val, ok = wing::next_header_value(map, "", "X-Empty-Flag", cursor);
        sub.assert_true(ok, "empty header value is found with ok=true");
        sub.assert_eq(val, "", "value slice is empty string");
        sub.assert_eq(cursor, -1, "cursor terminates at -1");
    };
}

fn main() {
    let runner = lit::new_runner("Headers Next Value Cursor Iteration Suite");

    lit::run_case(runner, "1. Single Header Cursor", test_single_header_cursor);
    lit::run_case(runner, "2. Multi-Value Header Cursor", test_multi_value_header_cursor);

    let ok = lit::finish(runner);
    assert(ok);
}
