// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_swar_headers.goose
// Verification of single-pass SWAR header delimiter and character scanner.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // 1. Valid header name scanning
    let valid_raw = "Content-Length: 42\r\n";
    let name_len, ok_name = wing::scan_header_field_name_swar(valid_raw);
    assert(ok_name);
    assert(name_len == 14);
    assert(valid_raw[..name_len] == "Content-Length");

    // 2. Valid header value scanning
    let val_slice = valid_raw[(name_len + 1)..]; // Skip ':'
    let val_len, crlf_len, ok_val = wing::scan_header_field_value_swar(val_slice);
    assert(ok_val);
    assert(crlf_len == 2);
    assert(core::trim_lws(val_slice[..val_len]) == "42");

    // 3. Header name with space before colon (RFC 9112 Section 5.1 violation)
    let bad_space_name = "Host : example.com\r\n";
    let _, ok_bad_name = wing::scan_header_field_name_swar(bad_space_name);
    assert(!ok_bad_name);

    // 4. Header value with embedded NUL (rejected)
    let bad_val_raw = "bad\x00val\r\n";
    let _, _, ok_bad_val = wing::scan_header_field_value_swar(bad_val_raw);
    assert(!ok_bad_val);

    // 5. Header value with tab (allowed per RFC 9110)
    let tab_val_raw = "text/plain;\tcharset=utf-8\r\n";
    let tab_len, tab_crlf, ok_tab = wing::scan_header_field_value_swar(tab_val_raw);
    assert(ok_tab);
    assert(tab_crlf == 2);
    assert(tab_len == 25);

    print("SWAR_HEADERS: OK");
}

// CHECK: SWAR_HEADERS: OK
