// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_sfv_rfc9651.goose
// Verification of RFC 9651 Structured Field Values: list inner-lists, parameterized inner items,
// decimal serialization, strict base64 quantum validation, and streaming String/DisplayString decoders.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import rfc from "../..";
import sfv from "../../http";
import headers from "../../http";
import chunked from "../../http/headers";
import chunked_fsm from "../../http/headers";
import h1 from "../../wire";

fn test_sfv_list_inner_lists_and_decimals() {
    var list_items: wing::SfParameterizedItem[..16] = [];
    let ok_list = wing::parse_sf_list("(\"a\";x=1 \"b\";y=2);lvl=3, 3.14, 2.500, -0.05", list_items);
    assert(ok_list);
    assert(list_items.len == 4);
    assert(list_items[0].is_inner_list);
    assert(list_items[0].inner_items.len == 2);
    assert(list_items[0].inner_items[0].str_val == "a");
    assert(list_items[0].inner_items[1].str_val == "b");
    assert(list_items[0].params.len == 1);
    assert(list_items[0].params[0].key == "lvl");
    assert(list_items[0].params[0].item.int_val == 3);

    var out: u8[..64] = [];
    wing::sf_serialize_item(list_items[1].item, out);
    assert(out[..] == "3.14");

    out.clear();
    wing::sf_serialize_item(list_items[2].item, out);
    assert(out[..] == "2.5");

    out.clear();
    wing::sf_serialize_item(list_items[3].item, out);
    assert(out[..] == "-0.05");
    print("SFV_INNER_LIST_AND_DECIMAL: OK");
}

fn test_sfv_base64_and_decoders() {
    var items: wing::SfParameterizedItem[..16] = [];
    assert(!wing::parse_sf_list(":===:", items));
    assert(!wing::parse_sf_list(":a=b:", items));
    assert(!wing::parse_sf_list(":abc:", items));
    assert(wing::parse_sf_list(":YWJj:", items));
    assert(wing::parse_sf_list(":YWI=:", items));
    assert(wing::parse_sf_list(":YQ==:", items));
    assert(wing::parse_sf_list("::", items));

    var unesc: u8[..64] = [];
    assert(wing::sf_unescape_string("hello \\\"world\\\" \\\\ok", unesc));
    assert(unesc[..] == "hello \"world\" \\ok");
    assert(!wing::sf_unescape_string("bad\\escape", unesc));

    var disp: u8[..64] = [];
    assert(wing::sf_decode_display_string("hello%20%c3%bc", disp));
    assert(disp[..] == "hello \xc3\xbc");
    assert(!wing::sf_decode_display_string("bad%2Ghex", disp));
    assert(!wing::sf_decode_display_string("bad%ffutf8", disp));
    assert(wing::sf_skip_ws_and_commas(" ,  a", 0) == 4);
    print("SFV_BASE64_AND_DECODERS: OK");
}

fn test_h1_wire_parsers() {
    assert(wing::swar_to_lower_64(0x4142434445464748) == 0x6162636465666768);
    var ch_b: u8 = 'A';
    assert(wing::is_field_name_byte_fast_lowercased(ch_b) && ch_b == 'a');

    var st_code: u16 = 0;
    assert(wire::parse_h1_wire_status_line("HTTP/1.1 200", st_code) && st_code == 200);
    let fn_len, fn_ok = wire::scan_h1_wire_field_name("X-Valid-Header: val\r\n");
    assert(fn_ok && fn_len == 14);
    let _, bad_fn = wire::scan_h1_wire_field_name("Bad@Header-Name: val\r\n");
    assert(!bad_fn);
    let _, bad_swar = wing::scan_header_field_name_swar("Bad/Header-Name: val\r\n");
    assert(!bad_swar);

    let m_conn, l_conn, ok_conn = wing::match_http_method_u32("CONNECT authority:443 HTTP/1.1\r\n");
    assert(ok_conn && m_conn == "CONNECT" && l_conn == 8);
    let m_opt, l_opt, ok_opt = wing::match_http_method_u32("OPTIONS * HTTP/1.1\r\n");
    assert(ok_opt && m_opt == "OPTIONS" && l_opt == 8);
    let m_trc, l_trc, ok_trc = wing::match_http_method_u32("TRACE / HTTP/1.1\r\n");
    assert(ok_trc && m_trc == "TRACE" && l_trc == 6);
    let m_pat, l_pat, ok_pat = wing::match_http_method_u32("PATCH /item HTTP/1.1\r\n");
    assert(ok_pat && m_pat == "PATCH" && l_pat == 6);

    var req_map = wing::HeaderMap { .. };
    let req_err = wing::parse_request_headers("\r\nGET / HTTP/1.1\r\nHost: example.com\r\nConnection: X-Custom\r\n\r\n", req_map);
    assert(req_err == wing::HeaderParseError.None && wing::get_header(req_map, "host") == "example.com");
    assert(!wing::is_continuation(req_map.entries[0]));
    assert(!wing::is_cookie_state(req_map.entries[0]));
    assert(!wing::is_security_state(req_map.entries[0]));
    assert(!wing::is_non_cacheable(req_map.entries[0]));
    var all_vals: u8[..256][>..] = [];
    wing::get_all_values(req_map, "host", all_vals);
    assert(all_vals.len == 1);
    var conn_toks: u8[..64][..32] = [];
    wing::collect_connection_tokens(req_map, conn_toks);
    assert(conn_toks.len == 1);

    var res_map = wing::HeaderMap { .. };
    let res_err = wing::parse_response_headers_with_mode(
        "ICY 200 OK\r\nicy-name : stream\r\n\r\n",
        res_map,
        wing::H1ResponseParseMode.ClientCompat,
    );
    assert(res_err == wing::HeaderParseError.None && res_map.status_code == 200);
    assert(wing::get_header(res_map, "icy-name") == "stream");

    assert(wing::is_chunk_overhead_excessive(120000, 102400));
    assert(!wing::is_chunk_overhead_excessive(500000, 102400));
    assert(internal::is_chunk_overhead_excessive(120000, 102400));
    print("H1_WIRE_PARSERS: OK");
}

fn main() {
    test_sfv_list_inner_lists_and_decimals();
    test_sfv_base64_and_decoders();
    test_h1_wire_parsers();
}

// CHECK: SFV_INNER_LIST_AND_DECIMAL: OK
// CHECK: SFV_BASE64_AND_DECODERS: OK
// CHECK: H1_WIRE_PARSERS: OK
