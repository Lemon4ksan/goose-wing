// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for Vulkan-style zero-copy cookie span parsing:
// 1. Single and multi-cookie extraction with next_cookie_span.
// 2. OWS whitespace and delimiter tolerance.
// 3. Valueless, nameless, and empty-value cookies.
// 4. Exact wire slice extraction via cookie_name and cookie_value.
// 5. Zero-allocation fast-path lookup via find_cookie_value.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_cookie_span_iteration(t: lit::T&) {
    t.run("Single Cookie Pair") { sub =>
        let raw: const u8[:] = "theme=dark";
        var cursor: i64 = 0;

        let span, ok = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok, "first cookie extracted");
        sub.assert_eq(wing::cookie_name(raw, span), "theme", "cookie name is 'theme'");
        sub.assert_eq(wing::cookie_value(raw, span), "dark", "cookie value is 'dark'");

        let span_end, ok_end = wing::next_cookie_span(raw, cursor);
        sub.assert_false(ok_end, "terminal contract: returns false at EOF");
    };

    t.run("Multi-Cookie Header with OWS") { sub =>
        let raw: const u8[:] = "sid=xyz123;   pref=auto; lang=ru-RU  ";
        var cursor: i64 = 0;

        // 1. sid
        let s1, ok1 = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok1);
        sub.assert_eq(wing::cookie_name(raw, s1), "sid");
        sub.assert_eq(wing::cookie_value(raw, s1), "xyz123");

        // 2. pref
        let s2, ok2 = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok2);
        sub.assert_eq(wing::cookie_name(raw, s2), "pref");
        sub.assert_eq(wing::cookie_value(raw, s2), "auto");

        // 3. lang
        let s3, ok3 = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok3);
        sub.assert_eq(wing::cookie_name(raw, s3), "lang");
        sub.assert_eq(wing::cookie_value(raw, s3), "ru-RU");

        // End
        let s4, ok4 = wing::next_cookie_span(raw, cursor);
        sub.assert_false(ok4);
    };

    t.run("Empty Value and Valueless Flag Cookies") { sub =>
        let raw: const u8[:] = "flag; empty=; full=1";
        var cursor: i64 = 0;

        // 1. flag (no '=')
        let s1, ok1 = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok1);
        sub.assert_eq(wing::cookie_name(raw, s1), "flag");
        sub.assert_eq(wing::cookie_value(raw, s1), "");

        // 2. empty= (empty value)
        let s2, ok2 = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok2);
        sub.assert_eq(wing::cookie_name(raw, s2), "empty");
        sub.assert_eq(wing::cookie_value(raw, s2), "");

        // 3. full=1
        let s3, ok3 = wing::next_cookie_span(raw, cursor);
        sub.assert_true(ok3);
        sub.assert_eq(wing::cookie_name(raw, s3), "full");
        sub.assert_eq(wing::cookie_value(raw, s3), "1");

        let _, ok4 = wing::next_cookie_span(raw, cursor);
        sub.assert_false(ok4);
    };
}

fn test_cookie_find_value(t: lit::T&) {
    t.run("Fast-Path find_cookie_value Lookup") { sub =>
        let raw: const u8[:] = "session=token999; theme=nord; consent=yes";

        let val_theme, ok_theme = wing::find_cookie_value(raw, "theme");
        sub.assert_true(ok_theme, "find theme succeeds");
        sub.assert_eq(val_theme, "nord", "theme is nord");

        let val_sess, ok_sess = wing::find_cookie_value(raw, "session");
        sub.assert_true(ok_sess, "find session succeeds");
        sub.assert_eq(val_sess, "token999", "session is token999");

        let val_consent, ok_consent = wing::find_cookie_value(raw, "consent");
        sub.assert_true(ok_consent, "find consent succeeds");
        sub.assert_eq(val_consent, "yes", "consent is yes");

        let val_missing, ok_missing = wing::find_cookie_value(raw, "nonexistent");
        sub.assert_false(ok_missing, "missing cookie returns false");
        sub.assert_eq(val_missing, "", "missing cookie value is empty");
    };
}

fn main() {
    let runner = lit::new_runner("Zero-Copy Cookie Span Parser Suite");

    lit::run_case(runner, "1. Cookie Span Iteration", test_cookie_span_iteration);
    lit::run_case(runner, "2. Fast-Path Cookie Lookup", test_cookie_find_value);

    let ok = lit::finish(runner);
    assert(ok);
}
