// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for Goose Core Byte String & Zero-Heap Slice Operations (core/bytes):
// - ASCII character classification & transformations (case.goose)
// - Case-insensitive folding, prefix/suffix, and substring search (case.goose)
// - Linear whitespace & ASCII whitespace trimming (trim.goose)
// - Byte set trimming and exact byte trimming (trim.goose)
// - Search predicates, byte indexing, slice indexing, and counting (search.goose)
// - Single-delimiter splitting, reverse splitting, and ByteTokenizer (split.goose)
// - Strict bounds-checked decimal and hex parsing with overflow protection (parse.goose)
// - Zero-allocation decimal and hex formatting (format.goose)
// - Universal Function Call Syntax (UFCS) method bridges (ufcs.goose)
import std;
import core from "..";

fn test_case_folding(t: core::T&) {
    t.run("ASCII Predicates & Character Conversions") { sub =>
        sub.assert_true(core::is_ascii_upper('A' as u8), "A is upper");
        sub.assert_true(core::is_ascii_upper('Z' as u8), "Z is upper");
        sub.assert_false(core::is_ascii_upper('a' as u8), "a is not upper");
        sub.assert_false(core::is_ascii_upper('9' as u8), "9 is not upper");

        sub.assert_true(core::is_ascii_lower('a' as u8), "a is lower");
        sub.assert_true(core::is_ascii_lower('z' as u8), "z is lower");
        sub.assert_false(core::is_ascii_lower('A' as u8), "A is not lower");

        sub.assert_true(core::is_ascii_alpha('g' as u8), "g is alpha");
        sub.assert_true(core::is_ascii_alpha('G' as u8), "G is alpha");
        sub.assert_false(core::is_ascii_alpha('5' as u8), "5 is not alpha");

        sub.assert_true(core::is_ascii_digit('0' as u8), "0 is digit");
        sub.assert_true(core::is_ascii_digit('9' as u8), "9 is digit");
        sub.assert_false(core::is_ascii_digit('x' as u8), "x is not digit");

        sub.assert_true(core::is_ascii_alphanumeric('k' as u8), "k is alnum");
        sub.assert_true(core::is_ascii_alphanumeric('7' as u8), "7 is alnum");
        sub.assert_false(core::is_ascii_alphanumeric('-' as u8), "- is not alnum");

        sub.assert_eq(core::to_lower_ascii_byte('M' as u8), 'm' as u8, "M -> m");
        sub.assert_eq(core::to_lower_ascii_byte('m' as u8), 'm' as u8, "m -> m");
        sub.assert_eq(core::to_upper_ascii_byte('w' as u8), 'W' as u8, "w -> W");
        sub.assert_eq(core::to_upper_ascii_byte('W' as u8), 'W' as u8, "W -> W");

        var lower_buf: u8[..64] = [];
        core::to_lower_ascii("GoOsE-WiNg v1.0!", lower_buf);
        sub.assert_eq(lower_buf[..], "goose-wing v1.0!", "to_lower_ascii string conversion");

        var upper_buf: u8[..64] = [];
        core::to_upper_ascii("goose-wing v1.0!", upper_buf);
        sub.assert_eq(upper_buf[..], "GOOSE-WING V1.0!", "to_upper_ascii string conversion");
    };

    t.run("Case-Insensitive Equality & Affixes") { sub =>
        let h1 = "Content-Type";
        let h2 = "content-type";
        let h3 = "CONTENT-TYPE";
        let h4 = "Content-Length";

        sub.assert_true(core::eq_ascii_fold(h1, h2), "h1 eq_fold h2");
        sub.assert_true(h1.eq_ascii_fold(h3), "h1.eq_ascii_fold(h3) via UFCS");
        sub.assert_false(core::eq_ascii_fold(h1, h4), "h1 not eq_fold h4");
        sub.assert_false(core::eq_ascii_fold(h1, "Content"), "Length mismatch false");

        sub.assert_true(core::starts_with_fold("Bearer token_xyz", "bearer"), "starts_with_fold prefix");
        sub.assert_true("BEARER token_xyz".starts_with_fold("bearer "), "starts_with_fold via UFCS");
        sub.assert_false(core::starts_with_fold("Basic user:pass", "bearer"), "starts_with_fold false prefix");

        sub.assert_true(core::ends_with_fold("image.JPEG", ".jpeg"), "ends_with_fold suffix");
        sub.assert_true("archive.tar.GZ".ends_with_fold(".gz"), "ends_with_fold via UFCS");
        sub.assert_false(core::ends_with_fold("document.pdf", ".png"), "ends_with_fold false suffix");

        let text = "The Quick Brown Fox Jumps Over The Lazy Dog";
        sub.assert_true(core::contains_fold(text, "brown fox"), "contains_fold match");
        sub.assert_true(text.contains_fold("LAZY"), "contains_fold via UFCS");
        sub.assert_false(core::contains_fold(text, "Cat"), "contains_fold no match");

        sub.assert_eq(core::index_of_fold(text, "brown"), 10, "index_of_fold matches index 10");
        sub.assert_eq(text.index_of_fold("FOX"), 16, "index_of_fold matches index 16");
        sub.assert_eq(core::index_of_fold(text, "tiger"), -1, "index_of_fold not found is -1");
    };
}

fn test_trimming(t: core::T&) {
    t.run("Linear White Space (RFC 9110 LWS)") { sub =>
        let raw = " \t  \tAuthorization: Bearer secret \t  ";
        sub.assert_eq(core::trim_lws_start(raw), "Authorization: Bearer secret \t  ", "trim_lws_start");
        sub.assert_eq(core::trim_lws_end(raw), " \t  \tAuthorization: Bearer secret", "trim_lws_end");
        sub.assert_eq(core::trim_lws(raw), "Authorization: Bearer secret", "trim_lws both ends");
        sub.assert_eq(raw.trim_lws(), "Authorization: Bearer secret", "trim_lws via UFCS");

        // Edge cases
        sub.assert_eq(core::trim_lws(""), "", "trim_lws on empty");
        sub.assert_eq(core::trim_lws("     \t\t "), "", "trim_lws all whitespace");
        sub.assert_eq(core::trim_lws("no_spaces"), "no_spaces", "trim_lws without whitespace");
    };

    t.run("ASCII Space Trimming (CR, LF, TAB, SP)") { sub =>
        let multiline = "\r\n  \t{\"status\": \"healthy\"}\n\r\t  ";
        sub.assert_eq(core::trim_ascii_space_start(multiline), "{\"status\": \"healthy\"}\n\r\t  ", "trim_ascii_space_start");
        sub.assert_eq(core::trim_ascii_space_end(multiline), "\r\n  \t{\"status\": \"healthy\"}", "trim_ascii_space_end");
        sub.assert_eq(core::trim_ascii_space(multiline), "{\"status\": \"healthy\"}", "trim_ascii_space both ends");
        sub.assert_eq(multiline.trim_ascii_space(), "{\"status\": \"healthy\"}", "trim_ascii_space via UFCS");
    };

    t.run("Byte and Cutset Trimming") { sub =>
        let slashed = "///api/v2/users///";
        sub.assert_eq(core::trim_start_byte(slashed, '/' as u8), "api/v2/users///", "trim_start_byte");
        sub.assert_eq(core::trim_end_byte(slashed, '/' as u8), "///api/v2/users", "trim_end_byte");
        sub.assert_eq(core::trim_byte(slashed, '/' as u8), "api/v2/users", "trim_byte both ends");
        sub.assert_eq(slashed.trim_byte('/' as u8), "api/v2/users", "trim_byte via UFCS");

        let enclosed = "[{\"key\":\"val\"}]";
        sub.assert_eq(core::trim_bytes(enclosed, "[]"), "{\"key\":\"val\"}", "trim_bytes cutset");
        sub.assert_eq(enclosed.trim_bytes("[]"), "{\"key\":\"val\"}", "trim_bytes via UFCS");

        let quotes = "\"\"quoted string\"\"";
        sub.assert_eq(quotes.trim_bytes("\""), "quoted string", "trim_bytes quotes");
    };
}

fn test_search_and_split(t: core::T&) {
    t.run("Byte Scanning and Predicates") { sub =>
        let path = "/api/v1/metrics/prometheus";
        sub.assert_true(core::starts_with(path, "/api"), "starts_with prefix");
        sub.assert_true(path.starts_with("/api/v1"), "starts_with via UFCS");
        sub.assert_false(path.starts_with("/auth"), "starts_with non-prefix");

        sub.assert_true(core::ends_with(path, "prometheus"), "ends_with suffix");
        sub.assert_true(path.ends_with("/prometheus"), "ends_with via UFCS");
        sub.assert_false(path.ends_with(".json"), "ends_with non-suffix");

        sub.assert_true(core::contains_byte(path, '@' as u8) == false, "does not contain @");
        sub.assert_true(path.contains_byte('/' as u8), "contains_byte via UFCS");
        sub.assert_eq(core::count_byte(path, '/' as u8), 4, "count_byte finds 4 slashes");
        sub.assert_eq(path.count_byte('/' as u8), 4, "count_byte via UFCS");

        sub.assert_eq(core::index_of_byte(path, 'v' as u8), 5, "index_of_byte 'v' at 5");
        sub.assert_eq(path.index_of_byte('v' as u8), 5, "index_of_byte via UFCS");
        sub.assert_eq(core::last_index_of_byte(path, '/' as u8), 15, "last_index_of_byte '/' at 15");
        sub.assert_eq(path.last_index_of_byte('/' as u8), 15, "last_index_of_byte via UFCS");

        sub.assert_eq(core::index_of_slice(path, "metrics"), 8, "index_of_slice finds 'metrics' at 8");
        sub.assert_eq(path.index_of_slice("metrics"), 8, "index_of_slice via UFCS");
        sub.assert_eq(core::index_of_slice(path, "missing"), -1, "index_of_slice missing is -1");
    };

    t.run("Split Once & Reverse Split Once") { sub =>
        let header = "Authorization: Bearer my_jwt_token";
        let left, right, found = core::split_once_byte(header, ':' as u8);
        sub.assert_true(found, "split_once_byte found colon");
        sub.assert_eq(left, "Authorization", "split_once_byte left");
        sub.assert_eq(right, " Bearer my_jwt_token", "split_once_byte right");

        let no_delim = "BareTokenWithoutDelim";
        let nd_left, nd_right, nd_found = no_delim.split_once_byte(':' as u8);
        sub.assert_false(nd_found, "split_once_byte not found");
        sub.assert_eq(nd_left, no_delim, "split_once_byte left is whole string");
        sub.assert_eq(nd_right, "", "split_once_byte right is empty");

        let file_path = "src/core/bytes/case.goose";
        let dir, file_name, r_found = file_path.rsplit_once_byte('/' as u8);
        sub.assert_true(r_found, "rsplit_once_byte found slash");
        sub.assert_eq(dir, "src/core/bytes", "rsplit_once_byte dir");
        sub.assert_eq(file_name, "case.goose", "rsplit_once_byte file_name");

        let wire_msg = "Content-Length: 42\r\n\r\n{\"ok\":true}";
        let headers_part, body_part, sep_found = wire_msg.split_once("\r\n\r\n");
        sub.assert_true(sep_found, "split_once found CRLFCRLF");
        sub.assert_eq(headers_part, "Content-Length: 42", "split_once headers");
        sub.assert_eq(body_part, "{\"ok\":true}", "split_once body");

        let fold_str = "Key=ValUE; charset=utf-8";
        let f_left, f_right, f_found = fold_str.split_once_fold("CHARSET=");
        sub.assert_true(f_found, "split_once_fold found CHARSET=");
        sub.assert_eq(f_left, "Key=ValUE; ", "split_once_fold left");
        sub.assert_eq(f_right, "utf-8", "split_once_fold right");
    };

    t.run("Zero-Allocation ByteTokenizer") { sub =>
        let csv = "alice,bob,carol,david";
        var tok = core::make_byte_tokenizer(csv, ',' as u8);

        let t1, ok1 = core::token_next(tok);
        sub.assert_true(ok1, "tok 1 ok");
        sub.assert_eq(t1, "alice", "tok 1 alice");

        let t2, ok2 = tok.token_next();
        sub.assert_true(ok2, "tok 2 ok");
        sub.assert_eq(t2, "bob", "tok 2 bob");

        let t3, ok3 = tok.token_next();
        sub.assert_true(ok3, "tok 3 ok");
        sub.assert_eq(t3, "carol", "tok 3 carol");

        let t4, ok4 = tok.token_next();
        sub.assert_true(ok4, "tok 4 ok");
        sub.assert_eq(t4, "david", "tok 4 david");

        let t5, ok5 = tok.token_next();
        sub.assert_false(ok5, "tok 5 exhausted");
        sub.assert_eq(t5, "", "tok 5 empty");

        // Edge case: single token
        var single_tok = core::make_byte_tokenizer("alone", ';');
        let st1, s_ok1 = single_tok.token_next();
        sub.assert_true(s_ok1, "single token ok");
        sub.assert_eq(st1, "alone", "single token matches");
        let _, s_ok2 = single_tok.token_next();
        sub.assert_false(s_ok2, "single token then exhausted");

        // Edge case: empty source
        var empty_tok = core::make_byte_tokenizer("", ',');
        let _, e_ok = empty_tok.token_next();
        sub.assert_false(e_ok, "empty source immediately exhausted");
    };
}

fn test_parsing_and_formatting(t: core::T&) {
    t.run("Decimal Integer Parsing") { sub =>
        let u_val, u_ok = core::parse_u64_dec("18446744073709551615");
        sub.assert_true(u_ok, "parse u64::MAX ok");
        sub.assert_eq(u_val, 18446744073709551615, "u64::MAX parsed accurately");

        let zero, z_ok = "0".parse_u64_dec();
        sub.assert_true(z_ok, "parse 0 ok via UFCS");
        sub.assert_eq(zero, 0, "0 matches");

        // Overflow check (u64::MAX + 1 -> 18446744073709551616)
        let _, of_ok = "18446744073709551616".parse_u64_dec();
        sub.assert_false(of_ok, "u64 overflow rejected");

        // Non-digit check
        let _, nd_ok = "123a45".parse_u64_dec();
        sub.assert_false(nd_ok, "non-digit rejected");

        // Signed i64 tests
        let pos_i, pos_ok = "+9223372036854775807".parse_i64_dec();
        sub.assert_true(pos_ok, "parse positive i64::MAX ok");
        sub.assert_eq(pos_i, 9223372036854775807, "i64::MAX matches");

        let neg_i, neg_ok = "-9223372036854775808".parse_i64_dec();
        sub.assert_true(neg_ok, "parse negative i64::MIN ok");
        sub.assert_eq(neg_i, -9223372036854775807 - 1, "i64::MIN matches");

        let _, i_of_ok = "9223372036854775808".parse_i64_dec();
        sub.assert_false(i_of_ok, "i64 positive overflow rejected");

        let _, i_uf_ok = "-9223372036854775809".parse_i64_dec();
        sub.assert_false(i_uf_ok, "i64 negative underflow rejected");

        // 32-bit integer parsing
        let u32_val, u32_ok = "4294967295".parse_u32_dec();
        sub.assert_true(u32_ok, "u32::MAX parsed");
        sub.assert_eq(u32_val, 4294967295, "u32::MAX matches");

        let _, u32_of = "4294967296".parse_u32_dec();
        sub.assert_false(u32_of, "u32 overflow rejected");

        let i32_val, i32_ok = "-2147483648".parse_i32_dec();
        sub.assert_true(i32_ok, "i32::MIN parsed");
        sub.assert_eq(i32_val, -2147483648, "i32::MIN matches");
    };

    t.run("Hexadecimal Integer Parsing") { sub =>
        let h1, ok1 = core::parse_u64_hex("deadbeef");
        sub.assert_true(ok1, "parse deadbeef hex ok");
        sub.assert_eq(h1, 0xdeadbeef, "deadbeef value matches");

        let h2, ok2 = "0xDEADBEEF".parse_u64_hex();
        sub.assert_true(ok2, "parse 0xDEADBEEF ok via UFCS");
        sub.assert_eq(h2, 0xdeadbeef, "0xDEADBEEF matches");

        let h_max, ok_max = "0xFFFFFFFFFFFFFFFF".parse_u64_hex();
        sub.assert_true(ok_max, "parse max u64 hex ok");
        sub.assert_eq(h_max, 18446744073709551615, "u64 hex max matches");

        let _, bad_hex = "0x123Z".parse_u64_hex();
        sub.assert_false(bad_hex, "invalid hex char Z rejected");

        let u8_val, u8_ok = "2A".parse_u8_hex();
        sub.assert_true(u8_ok, "u8 hex 2A ok");
        sub.assert_eq(u8_val, 42 as u8, "2A is 42");
    };

    t.run("Decimal & Hexadecimal Formatting") { sub =>
        var dec_buf: u8[..64] = [];
        core::format_u64_dec(18446744073709551615, dec_buf);
        sub.assert_eq(dec_buf[..], "18446744073709551615", "format_u64_dec max matches");

        var zero_buf: u8[..16] = [];
        core::format_u64_dec(0, zero_buf);
        sub.assert_eq(zero_buf[..], "0", "format_u64_dec 0 matches");

        var neg_buf: u8[..64] = [];
        core::format_i64_dec(-9223372036854775807 - 1, neg_buf);
        sub.assert_eq(neg_buf[..], "-9223372036854775808", "format_i64_dec i64::MIN matches");

        var hex_lower: u8[..32] = [];
        core::format_u64_hex(0xfeedface, hex_lower, false);
        sub.assert_eq(hex_lower[..], "feedface", "format_u64_hex lowercase");

        var hex_upper: u8[..32] = [];
        core::format_u64_hex(0xfeedface, hex_upper, true);
        sub.assert_eq(hex_upper[..], "FEEDFACE", "format_u64_hex uppercase");

        var byte_buf: u8[..8] = [];
        core::format_u8_hex(0x0a as u8, byte_buf, false);
        sub.assert_eq(byte_buf[..], "0a", "format_u8_hex leading zero padded");

        var fixed_buf: u8[..32] = [];
        core::format_u64_hex_fixed(0x42, 6, fixed_buf, true);
        sub.assert_eq(fixed_buf[..], "000042", "format_u64_hex_fixed 6-digit zero padding");
    };
}

fn main() {
    var runner = core::new_runner("Goose Core Byte String & Zero-Heap Slice Operations Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. ASCII Predicates, Case Conversions & Folding", test_case_folding);
    core::run_case(runner, "2. Linear Whitespace, ASCII Whitespace & Byte Trimming", test_trimming);
    core::run_case(runner, "3. Byte Search, Slice Splitting & ByteTokenizer", test_search_and_split);
    core::run_case(runner, "4. Bounds-Checked Decimal & Hex Parsing and Formatting", test_parsing_and_formatting);
    let ok = core::finish(runner);
    assert(ok);
}
