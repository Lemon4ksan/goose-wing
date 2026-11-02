// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_fast_string_primitives.goose
// Verification of zero-allocation string primitives: SIMD packed-pair search,
// byteset membership scans, 64-bit SWAR case conversion, and RFC 3629 UTF-8 decoding.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";

fn main() {
    // 1. Equal short verification
    assert(core::equal_short("Content-Type", "Content-Type"));
    assert(!core::equal_short("Content-Type", "Content-Length"));
    assert(core::starts_with("Bearer token123", "Bearer "));
    assert(core::ends_with("index.html", ".html"));

    // 2. Substring search (SIMD packed-pair + Two-Way)
    let text = "GET /api/v1/orders HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert(core::find(text, "orders") == 12);
    assert(core::find(text, "HTTP/1.1") == 19);
    assert(core::find(text, "missing") == -1);
    assert(core::rfind(text, "/") == 23);
    assert(core::contains(text, "example.com"));

    // 3. ByteSet search and trim
    let raw = " \t\r\n  key = value \t\r\n ";
    let cutset = " \t\r\n";
    let trimmed = core::trim_bytes(raw, cutset);
    assert(trimmed == "key = value");
    assert(core::find_byteset("foo::bar", ":/") == 3);
    assert(core::find_not_byteset("   abc", " ") == 3);
    assert(core::rfind_byteset("abc,def;ghi", ",;") == 7);
    assert(core::rfind_not_byteset("name \t ", " \t") == 3);

    // 4. In-place SWAR case conversion
    var buf: u8[32] = [0; 32];
    let sample = "HTTP/1.1 200 OK";
    for i in sample.len { buf[i] = sample[i]; }
    core::make_ascii_lowercase(buf[..sample.len]);
    assert(buf[..sample.len] == "http/1.1 200 ok");
    core::make_ascii_uppercase(buf[..sample.len]);
    assert(buf[..sample.len] == "HTTP/1.1 200 OK");

    // 5. UTF-8 scalar decoding (maximal subpart replacement)
    let cp1, sz1, ok1 = core::decode_utf8("café");
    assert(cp1 == 99 && sz1 == 1 && ok1);

    let cp2, sz2, ok2 = core::decode_utf8("é");
    assert(cp2 == 0xE9 && sz2 == 2 && ok2);

    let cp_last, sz_last, ok_last = core::decode_last_utf8("!é");
    assert(cp_last == 0xE9 && sz_last == 2 && ok_last);

    let cp_lossy, sz_lossy = core::decode_utf8_lossy("\xE2\x82!");
    assert(cp_lossy == 0xFFFD && sz_lossy == 2);

    let cp_llossy, sz_llossy = core::decode_last_utf8_lossy("!\xE2\x82");
    assert(cp_llossy == 0xFFFD && sz_llossy == 2);

    let cp_bad, sz_bad, ok_bad = core::decode_utf8("\xFFabc");
    assert(cp_bad == 0xFFFD && sz_bad == 1 && !ok_bad);

    var count = 0;
    core::char_indices("aé\xFF") { start, end, cp =>
        count++;
    };
    assert(count == 3);

    print("FAST_STRING_PRIMITIVES: PASS");
}

// CHECK: FAST_STRING_PRIMITIVES: PASS
