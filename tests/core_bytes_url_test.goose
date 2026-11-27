// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite: core/bytes and core/url deep edge & RFC boundary coverage.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import json;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_bytes_utf8_and_json(t: lit::T&) {
    t.run("UTF-8 validator, SWAR ASCII skips, streaming DFA, decode & lossy") { sub =>
        sub.assert_true(core::is_pure_ascii(""));
        sub.assert_eq(core::find_crlf("a"), -1);

        // 2-byte, 3-byte, 4-byte valid + invalid sequences in validate_utf8 / decode_utf8 / decode_last_utf8
        let v3:          u8[3] = [0xE2, 0x82, 0xAC]; // U+20AC
        let v4:          u8[4] = [0xF0, 0x9F, 0x98, 0x80]; // U+1F600
        let bad_3_cont:  u8[3] = [0xE2, 0x82, 0x41];
        let bad_4_trunc: u8[3] = [0xF0, 0x9F, 0x98];
        let bad_4_cont:  u8[4] = [0xF0, 0x9F, 0x98, 0x41];
        let bad_4_over:  u8[4] = [0xF0, 0x80, 0x80, 0x80];
        let bad_4_high:  u8[4] = [0xF4, 0x90, 0x80, 0x80];
        let bad_lead:    u8[4] = [0xF5, 0x80, 0x80, 0x80];

        sub.assert_true(core::validate_utf8(v3[..]) && core::validate_utf8(v4[..]));
        sub.assert_false(core::validate_utf8(bad_3_cont[..]));
        sub.assert_false(core::validate_utf8(bad_4_trunc[..]));
        sub.assert_false(core::validate_utf8(bad_4_cont[..]));
        sub.assert_false(core::validate_utf8(bad_4_over[..]));
        sub.assert_false(core::validate_utf8(bad_4_high[..]));
        sub.assert_false(core::validate_utf8(bad_lead[..]));

        // validate_utf8_dfa_chunk sticky reject & skip_utf8_dfa_ascii_run
        var dfa_st: u8 = core::UTF8_DFA_REJECT;
        sub.assert_false(core::validate_utf8_dfa_chunk("abc", dfa_st, true));
        dfa_st = 0;
        var mixed24: u8[24] = ['x'; 24];
        mixed24[18] = 0xC3;
        mixed24[19] = 0xA9;
        sub.assert_true(core::validate_utf8_dfa_chunk(mixed24[..], dfa_st, true));
        dfa_st = 0;
        sub.assert_true(core::validate_utf8_dfa_chunk(mixed24[..22], dfa_st, true));

        // decode_utf8 / decode_last_utf8 edge cases + char_indices
        let _, _, ok_de = core::decode_utf8("");
        let _, _, ok_dl_e = core::decode_last_utf8("");
        let _, _, ok_dl_tr = core::decode_last_utf8(bad_4_trunc[..]);
        let _, _, ok_d_sur = core::decode_utf8("\xED\xA0\x80");
        sub.assert_false(ok_de || ok_dl_e || ok_dl_tr || ok_d_sur);
        var cp_cnt: i64 = 0;
        core::char_indices(v4[..]) { _idx, _end, _cp => cp_cnt += 1; };
        sub.assert_eq(cp_cnt, 1);
    };

    t.run("Bounded JSON escaping, formatting, unicode decoding & reader guards") { sub =>
        var esc_out: u8[..64] = [];
        let ctrl_str: u8[9] = ['"', '\\', '\r', '\n', '\t', 8, 12, 1, 'a'];
        sub.assert_true(core::try_format_json_string(esc_out, ctrl_str[..]));
        sub.assert_true(core::contains(esc_out[..], "\\f") && core::contains(esc_out[..], "\\u0001"));
        esc_out.clear();
        sub.assert_true(core::try_format_json_key(esc_out, ctrl_str[..]));
        sub.assert_true(esc_out[..].ends_with(":"));

        var tiny: u8[..3] = [];
        sub.assert_false(core::try_format_json_string(tiny, "abcd"));
        sub.assert_eq(tiny.len, 0);
        sub.assert_false(core::try_format_json_key(tiny, "ab\"c"));
        sub.assert_eq(tiny.len, 0);

        // Surrogate pairs, bad hex, raw control chars, overflow rollback, invalid UTF-8
        var j_dst: u8[..32] = [];
        let s_all = "\\\"\\\\\\r\\n\\t\\b\\f\\/\\u0041\\uD83D\\uDE00";
        sub.assert_true(core::decode_json_string_into(s_all, 0, s_all.len, j_dst));
        sub.assert_true(core::validate_utf8(j_dst[..]));

        let bad_raw_ctrl: u8[1] = [0x05];
        sub.assert_false(core::decode_json_string_into(bad_raw_ctrl[..], 0, 1, j_dst));
        sub.assert_false(core::decode_json_string_into("abc", -1, 2, j_dst));
        sub.assert_false(core::decode_json_string_into("\\u12", 0, 4, j_dst));
        sub.assert_false(core::decode_json_string_into("\\uZZZZ", 0, 6, j_dst));
        sub.assert_false(core::decode_json_string_into("\\uD83D", 0, 6, j_dst));
        sub.assert_false(core::decode_json_string_into("\\uD83D\\u0041", 0, 12, j_dst));
        sub.assert_false(core::decode_json_string_into("\\uD83D\\uDE00", 0, 12, tiny));

        // Direct read_json_string_into with invalid UTF-8
        let bad_json_u8: u8[4] = ['"', 0xFF, 0xFF, '"'];
        var jr = json::Reader { text: bad_json_u8[..], .. };
        sub.assert_false(core::read_json_string_into(jr, j_dst));
        var good_jr = json::Reader { text: "\"\\u0041\"", .. };
        sub.assert_true(core::read_json_string_into(good_jr, j_dst));
    };

    t.run("Bytes search/rfind/byteset/split/parse/case/trim/lexical/format") { sub =>
        sub.assert_true(core::equal_short("", ""));
        sub.assert_eq(core::count_byte("", 'a'), 0);
        sub.assert_eq(core::find("abc", ""), 0);
        sub.assert_eq(core::rfind("abc", ""), 3);
        sub.assert_eq(core::rfind("abc", "abcd"), -1);

        // Inverted / empty byteset & rfind Two-Way (>32B periodic and non-periodic needles)
        sub.assert_eq(core::byteset_find("abc", "", true), 0);
        sub.assert_eq(core::byteset_find("abc", "", false), -1);
        sub.assert_eq(core::byteset_rfind("", "a", false), -1);
        sub.assert_eq(core::byteset_rfind("abc", "", true), 2);
        sub.assert_eq(core::byteset_rfind("abc", "", false), -1);
        sub.assert_eq(core::byteset_rfind("abca", "a", false), 3);
        sub.assert_eq(core::byteset_rfind("aaab", "a", true), 3);

        let long_per = "ababababababababababababababababababab"; // 38B periodic
        let long_nonper = "0123456789abcdefghijklmnopqrstuvwxyz!@#"; // 39B non-periodic
        var hay: u8[..256] = [];
        hay.append("prefix---");
        hay.append(long_per);
        hay.append("---mid---");
        hay.append(long_per);
        hay.append("---");
        hay.append(long_nonper);
        sub.assert_gt(core::find(hay[..], long_per), 0);
        sub.assert_gt(core::rfind(hay[..], long_per), 15);
        sub.assert_gt(core::rfind(hay[..], long_nonper), 15);
        sub.assert_eq(core::rfind("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", long_nonper), -1);

        // split / collapse / parse / case / trim / format
        let _, _, ok_se = core::split_once("abc", "");
        sub.assert_false(ok_se);
        let p_l, p_r, p_ok = core::split_once("a::b", "::");
        sub.assert_true(p_ok && p_l == "a" && p_r == "b");

        var pair_n: i64 = 0;
        core::each_pair("a") { _a, _b => pair_n += 1; };
        sub.assert_eq(pair_n, 0);
        core::each_window("abc", 5) { _w, _idx => pair_n += 1; };
        sub.assert_eq(pair_n, 0);

        var col_buf: u8[8] = ['a', '/', '/', '/', 'b', 'c', '/', '/'];
        let cl = core::collapse_repeats_in_place(col_buf[..], '/');
        sub.assert_bytes_eq(col_buf[..cl], "a/bc/");

        var tok = core::make_byte_tokenizer("a,b", ',');
        let _, _ = core::token_next(tok);
        sub.assert_bytes_eq(core::token_rest(tok), "b");
        let _, _ = core::token_next(tok);
        let _, ok_pk = core::token_peek(tok);
        sub.assert_false(ok_pk);

        let _, ok_i64 = core::parse_i64_dec("-");
        let _, ok_uh = core::parse_u64_hex("");
        let _, ok_u32h = core::parse_u32_hex("100000000");
        let _, ok_u8h = core::parse_u8_hex("100");
        sub.assert_false(ok_i64 || ok_uh || ok_u32h || ok_u8h);

        var eb: u8[0] = [];
        core::make_ascii_lowercase(eb[..]);
        core::make_ascii_uppercase(eb[..]);
        sub.assert_eq(core::index_of_fold("abc", ""), 0);
        sub.assert_bytes_eq(core::trim_end_bytes("///", "/"), "");
        var fx: u8[..16] = [];
        core::format_u64_hex_fixed(15 as u64, 0, fx, false);
        sub.assert_eq(fx.len, 0);
    };
}

fn test_url_full_edges(t: lit::T&) {
    t.run("URL path builders, endpoint, IDNA/Punycode, IP/CIDR, Query & Origin") { sub =>
        let base = core::new_url("https://user:pass@example.com:8080/a/b/file.txt?q=1#h");
        let inv_u = core::new_url("");
        sub.assert_false(inv_u.valid);
        let v0 = core::UrlView { raw: "http://x/", .. };
        sub.assert_bytes_eq(core::href(v0), "http://x/");
        sub.assert_false(core::is_valid(v0));

        // parse_endpoint
        let _, err_ep_bad = core::parse_endpoint(inv_u, "/v1");
        sub.assert_true(err_ep_bad != core::UrlParseError.None);
        let ep_q, err_ep_q = core::parse_endpoint(base, "?only=query");
        sub.assert_true(err_ep_q == core::UrlParseError.None && core::contains(ep_q.href[..], "?only=query"));

        // percent_decode empty
        var tiny4: u8[..4] = [];
        sub.assert_true(core::percent_decode("", tiny4));

        // IP / CIDR / zone-id & scoped IPv6 edges
        let _, ok_cidr_bad1 = core::parse_cidr("noslash");
        let _, ok_cidr_bad2 = core::parse_cidr("badip/24");
        let _, ok_cidr_bad3 = core::parse_cidr("10.0.0.1/99");
        sub.assert_false(ok_cidr_bad1 || ok_cidr_bad2 || ok_cidr_bad3);
        let c25, ok_c25 = core::parse_cidr("192.168.1.128/25");
        let c24, _ = core::parse_cidr("192.168.1.0/24");
        let ip_out, _ = core::parse_ip_addr("192.168.1.10");
        let ip_in, _ = core::parse_ip_addr("192.168.1.200");
        let ip_v6, _ = core::parse_ip_addr("[2001:db8::1]");
        sub.assert_true(ok_c25 && core::cidr_contains_ip(c25, ip_in) && !core::cidr_contains_ip(c25, ip_out));
        sub.assert_true(core::cidr_contains_cidr(c24, c25));
        sub.assert_false(core::ip_addr_equals(ip_in, ip_out));
        sub.assert_false(core::ip_addr_equals(ip_in, ip_v6));
        sub.assert_false(core::validate_zone_id(""));
        sub.assert_false(core::validate_zone_id("eth%zz"));

        // IDNA / Punycode encoding & decoding + validation failures
        var ace_dom: u8[..256] = [];
        sub.assert_true(core::punycode_encode_domain("bücher.example", ace_dom));
        sub.assert_true(ace_dom[..].starts_with("xn--bcher-kva"));
        sub.assert_false(core::punycode_encode_domain("", ace_dom));
        sub.assert_false(core::punycode_encode_domain(".bad.com", ace_dom));
        sub.assert_false(core::punycode_encode_domain("127.0.0.1", ace_dom));
        sub.assert_false(core::validate_host_punycode_labels("xn--bad_non_ascii_$.com"));
        sub.assert_false(core::validate_host_punycode_labels("xn--9999999999z.com"));

        // Origins, opaque origins, serialize_origin
        let o_bad = core::new_origin_tuple("", "example.com", 80);
        sub.assert_true(o_bad.kind == core::OriginKind.Opaque);
        let o_v6 = core::new_origin_tuple("https", "2001:db8::1", 8443);
        var o_str: u8[..128] = [];
        core::serialize_origin(o_v6, o_str);
        sub.assert_bytes_eq(o_str[..], "https://[2001:db8::1]:8443");
        let u_ftp = core::new_url("ftp://ftp.example.com/a");
        sub.assert_eq(core::effective_port(u_ftp), 21);

        // normalize_http_target_uri & query helpers (RFC 9449 §4.2 strips query/fragment)
        var norm_u: u8[..512] = [];
        sub.assert_true(core::normalize_http_target_uri("https://Example.COM:443/p?a=1", norm_u));
        sub.assert_bytes_eq(norm_u[..], "https://example.com/p");
        var norm_tiny: u8[..10] = [];
        sub.assert_false(core::normalize_http_target_uri("https://example.com/very/long/path", norm_tiny));

        var dec_f: u8[..256] = [];
        sub.assert_true(core::decode_form_urlencoded("a+b%20c", dec_f) && dec_f[..] == "a b c");
        sub.assert_false(core::decode_form_urlencoded("bad%ZZ", dec_f));
        sub.assert_false(core::decode_form_urlencoded("bad%00", dec_f));
        var qv: u8[..16] = [];
        sub.assert_true(core::get_query_param_fast("&&flag&&k=v", "k", qv) == core::QueryParamMatch.Value);
        sub.assert_true(core::has_query_param_fast("&&flag&&k=v", "flag"));
    };
}

fn main() {
    let runner = lit::new_runner("Core Bytes and URL Verification Suite");
    lit::run_case(runner, "1. Bytes UTF-8, JSON, Search, Split & Lexical", test_bytes_utf8_and_json);
    lit::run_case(runner, "2. URL Path, File, IDNA, IP/CIDR, Query & Origin", test_url_full_edges);
    assert(lit::finish(runner));
}
