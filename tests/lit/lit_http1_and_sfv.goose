// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_http1_and_sfv
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_http1_chunked (1/10)
// ============================================================================
// CHECK: === [1/10] verify_http1_chunked ===

// tests/lit/verify_http1_chunked.goose
// Verification of RFC 9112 Chunked Transfer Coding and Single-Register FSM via wing.
//

// Wire adapter for verify_split_stream and fuzzing using wing's internal 64-bit FSM decoder
fn wing_parse_http1_chunk_frame(buf: const u8[:]) -> i64 {
    var dec = http_internal::new_chunk_fsm_decoder();
    let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, buf);
    match st {
        YieldChunk => {
            if dec.state == http_internal::CHUNK_STATE_IS_CHUNKED && consumed == buf.len {
                return chunk.len;
            }
            return -1;
        },
        Complete => {
            if consumed == buf.len {
                return 0;
            }
            return -1;
        },
        NeedMore => {
            return -1;
        },
        Error => {
            return -2;
        },
    }
}

fn calc_chunk_step(size: i64, digit: i64) -> i64 {
    return (size << 4) | (digit & 15);
}

fn calc_chunk_overhead(chunk_len: i64, has_ext: i64) -> i64 {
    return chunk_len + 4 + (has_ext & 8);
}

fn run_01_verify_http1_chunked() {
    let chunk5 = "5\r\nHello\r\n";
    assert(wire_kit::verify_split_stream(chunk5, -1, 5, wing_parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk5, 100, wing_parse_http1_chunk_frame));

    let chunk0_pipe = "0\r\n\r\n";
    assert(wire_kit::verify_split_stream(chunk0_pipe, -1, 0, wing_parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk0_pipe, 100, wing_parse_http1_chunk_frame));
    assert(wing_parse_http1_chunk_frame(chunk0_pipe) == 0);

    let chunk4_ext = "4;ext=1\r\nWiki\r\n";
    assert(wire_kit::verify_split_stream(chunk4_ext, -1, 4, wing_parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk4_ext, 100, wing_parse_http1_chunk_frame));
    print("HTTP1_CHUNK_SPLIT: OK");

    var vA: u8[>..] = []; wire_kit::parse_hex("350A48656C6C6F0D0A", vA);
    assert(wing_parse_http1_chunk_frame(vA[..]) == -2);

    var vB: u8[>..] = []; wire_kit::parse_hex("353B780A48656C6C6F0D0A", vB);
    assert(wing_parse_http1_chunk_frame(vB[..]) == -2);

    var vC: u8[>..] = []; wire_kit::parse_hex("35470D0A", vC);
    assert(wing_parse_http1_chunk_frame(vC[..]) == -2);

    var vD: u8[>..] = []; wire_kit::parse_hex("340D0A57696B695858", vD);
    assert(wing_parse_http1_chunk_frame(vD[..]) == -2);

    var vE: u8[>..] = []; wire_kit::parse_hex("3130300D0A01020304", vE);
    assert(wing_parse_http1_chunk_frame(vE[..]) == -1);
    print("HTTP1_CHUNK_SECURITY: OK");

    assert(calc_chunk_step(16, 10) == 266);
    assert(calc_chunk_overhead(100, 1) == 104);
    print("HTTP1_CHUNK_ALL: PASS");
}

// CHECK: HTTP1_CHUNK_SPLIT: OK
// CHECK: HTTP1_CHUNK_SECURITY: OK
// CHECK: HTTP1_CHUNK_ALL: PASS

// ============================================================================
// 2. verify_sfv_rfc9651 (2/10)
// ============================================================================
// CHECK: === [2/10] verify_sfv_rfc9651 ===

// tests/lit/verify_sfv_rfc9651.goose
// Verification of RFC 9651 Structured Field Values: list inner-lists, parameterized inner items,
// decimal serialization, strict base64 quantum validation, and streaming String/DisplayString decoders.
//

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
    print("H1_WIRE_PARSERS: OK");
}

fn run_02_verify_sfv_rfc9651() {
    test_sfv_list_inner_lists_and_decimals();
    test_sfv_base64_and_decoders();
    test_h1_wire_parsers();
}

// CHECK: SFV_INNER_LIST_AND_DECIMAL: OK
// CHECK: SFV_BASE64_AND_DECODERS: OK
// CHECK: H1_WIRE_PARSERS: OK

// ============================================================================
// 3. verify_http_extensions_edge (3/10)
// ============================================================================
// CHECK: === [3/10] verify_http_extensions_edge ===

// tests/lit/verify_http_extensions_edge.goose
// Verification of RFC 8288 Link header and RFC 8941 Structured Fields upload boolean via wing::http.
//

// Wire validator for RFC 8288 Link header using wing::parse_link_header
fn wing_validate_link_header_wire(buf: const u8[:]) -> i64 {
    guard buf.len >= 2 else { return -1; }
    guard buf[0] == '<' else { return -2; }
    var links: wing::EarlyHintLink[..8] = [];
    if wing::parse_link_header(buf, links) {
        guard links.len > 0 && links[0].uri.len > 0 else { return -3; }
        return links[0].uri.len;
    }
    let end_idx = core::index_of_byte(buf, '>');
    guard end_idx >= 0 else { return -1; }
    let uri_len = end_idx - 1;
    guard uri_len > 0 else { return -3; }
    return -4;
}

// RFC 8941 Structured Fields boolean validator for Resumable Uploads
fn validate_upload_boolean_wire(buf: const u8[:]) -> i32 {
    let len = buf.len;
    guard len >= 2 else { return -1; }
    guard buf[0] == '?' else { return -2; }
    let val_b = buf[1];
    guard val_b == '0' || val_b == '1' else { return -2; }

    if len == 2 {
        return if val_b == '1' { 1 } else { 0 };
    }

    let next_b = buf[2];
    guard next_b == ';' || next_b == ',' || next_b == ' ' || next_b == '\t' else {
        return -2;
    }

    return if val_b == '1' { 1 } else { 0 };
}

fn run_03_verify_http_extensions_edge() {
    let link_hdr = "<https://example.com/style.css>";
    assert(wire_kit::verify_split_stream(link_hdr, -1, 29, wing_validate_link_header_wire));
    assert(wire_kit::fuzz_payload(link_hdr, 100, wing_validate_link_header_wire));
    print("HTTP_LINK_SPLIT: OK");

    assert(wing_validate_link_header_wire("<>") == -3);
    assert(wing_validate_link_header_wire("<foo>bar; rel=preload") == -4);
    print("HTTP_LINK_SYNTAX: OK");

    assert(validate_upload_boolean_wire("?1") == 1);
    assert(validate_upload_boolean_wire("?0") == 0);
    assert(validate_upload_boolean_wire("?1; foo") == 1);
    assert(validate_upload_boolean_wire("?1abc") == -2);
    assert(validate_upload_boolean_wire("?2") == -2);
    print("HTTP_UPLOAD_BOOL: OK");
}

// CHECK: HTTP_LINK_SPLIT: OK
// CHECK: HTTP_LINK_SYNTAX: OK
// CHECK: HTTP_UPLOAD_BOOL: OK

// ============================================================================
// 4. verify_http_incremental (4/10)
// ============================================================================
// CHECK: === [4/10] verify_http_incremental ===

// tests/lit/verify_http_incremental.goose
// Verification of RFC 10036 Incremental Forwarding of HTTP Messages:
// - Boolean Item parsing (?1 / ?0)
// - Parameter ignoring rule (RFC 10036 §2)
// - Strict rejection of non-boolean types (RFC 10036 §2)
// - Intermediary Proxy-Status error signaling (incremental_refused & connection_limit_reached)
//

fn run_04_verify_http_incremental() {
    // 1. Valid Boolean Items
    let inc1, ok1 = wing::parse_incremental_header("?1");
    assert(ok1);
    assert(inc1);
    print("INC_TRUE: 1");
    // CHECK: INC_TRUE: 1

    let inc0, ok0 = wing::parse_incremental_header("?0");
    assert(ok0);
    assert(!inc0);
    print("INC_FALSE: 1");
    // CHECK: INC_FALSE: 1

    // 2. Parameters ignored per RFC 10036 §2
    let inc_param, ok_param = wing::parse_incremental_header("?1; param=value");
    assert(ok_param);
    assert(inc_param);
    print("INC_PARAM_IGNORED: 1");
    // CHECK: INC_PARAM_IGNORED: 1

    // 3. Non-Boolean types must be ignored (RFC 10036 §2)
    let _, ok_int = wing::parse_incremental_header("1");
    assert(!ok_int);

    let _, ok_str = wing::parse_incremental_header("\"?1\"");
    assert(!ok_str);

    let _, ok_tok = wing::parse_incremental_header("true");
    assert(!ok_tok);
    print("NON_BOOLEAN_IGNORED: 1");
    // CHECK: NON_BOOLEAN_IGNORED: 1

    // 4. HeaderMap inspection
    var headers = wing::HeaderMap { .. };
    wing::append_incremental_header(headers, true);
    assert(wing::is_incremental_requested(headers));
    print("HEADER_MAP_INCREMENTAL: 1");
    // CHECK: HEADER_MAP_INCREMENTAL: 1

    // 5. Intermediary incremental_refused Proxy-Status
    var ps_refused: u8[..128] = [];
    wing::format_incremental_refused_proxy_status(ps_refused, "edge-proxy");
    assert(core::contains(ps_refused[..], "edge-proxy"));
    assert(core::contains(ps_refused[..], "error=incremental_refused"));
    print("PROXY_STATUS_REFUSED: 1");
    // CHECK: PROXY_STATUS_REFUSED: 1

    // 6. Intermediary connection_limit_reached Proxy-Status
    var ps_limited: u8[..128] = [];
    wing::format_incremental_limit_reached_proxy_status(ps_limited, "edge-proxy");
    assert(core::contains(ps_limited[..], "edge-proxy"));
    assert(core::contains(ps_limited[..], "error=connection_limit_reached"));
    print("PROXY_STATUS_LIMITED: 1");
    // CHECK: PROXY_STATUS_LIMITED: 1

    print("RFC10036_VERIFICATION_COMPLETE");
    // CHECK: RFC10036_VERIFICATION_COMPLETE
}

// ============================================================================
// 5. verify_http_problem_and_forwarded (5/10)
// ============================================================================
// CHECK: === [5/10] verify_http_problem_and_forwarded ===

// tests/lit/verify_http_problem_and_forwarded.goose
// Verification of:
// - RFC 9457 Problem Details for HTTP APIs (application/problem+json)
// - RFC 7239 Forwarded HTTP Extension (IPv4, IPv6 quoted, proto, host, by)
// - RFC 8470 0-RTT Early-Data & HTTP 425 (Too Early) Recovery
// - RFC 6585, RFC 7725, RFC 9110 Standard Status Code Reason Phrases
//

fn test_rfc9457_problem_details() {
    // 1. Serialization with explicit type URI
    var prob = wing::ProblemDetails {
        status:   403,
        type_uri: "https://example.com/probs/out-of-credit",
        title:    "You do not have enough credit.",
        detail:   "Your current balance is 30, but that costs 50.",
        instance: "/account/12345/msgs/abc",
    };
    var json_out: u8[..1024] = [];
    wing::serialize_problem_details(prob, json_out);
    assert(core::contains(json_out[..], "\"status\":403"));
    assert(core::contains(json_out[..], "\"type\":\"https://example.com/probs/out-of-credit\""));
    assert(core::contains(json_out[..], "\"title\":\"You do not have enough credit.\""));
    assert(core::contains(json_out[..], "\"instance\":\"/account/12345/msgs/abc\""));
    print("PROBLEM_SERIALIZE_OK: 1");
    // CHECK: PROBLEM_SERIALIZE_OK: 1

    // 2. Default type URI "about:blank" (RFC 9457 §4.2.1)
    var blank_prob = wing::ProblemDetails {
        status: 404,
        title:  "Item Not Found",
        ..
    };
    var blank_out: u8[..512] = [];
    wing::serialize_problem_details(blank_prob, blank_out);
    assert(core::contains(blank_out[..], "\"type\":\"about:blank\""));
    print("PROBLEM_DEFAULT_TYPE_OK: 1");
    // CHECK: PROBLEM_DEFAULT_TYPE_OK: 1

    // 3. Problem response constructor
    let res = wing::new_problem_response(prob);
    assert(res.status_code == 403);
    assert(wing::header(res, "Content-Type") == "application/problem+json");
    print("PROBLEM_RESPONSE_OK: 1");
    // CHECK: PROBLEM_RESPONSE_OK: 1

    // 4. Parsing problem details JSON
    var parsed = wing::ProblemDetails { .. };
    let ok_parse = wing::parse_problem_details(json_out[..], parsed);
    assert(ok_parse);
    assert(parsed.status == 403);
    assert(parsed.title[..] == "You do not have enough credit.");
    assert(parsed.instance[..] == "/account/12345/msgs/abc");
    print("PROBLEM_PARSE_OK: 1");
    // CHECK: PROBLEM_PARSE_OK: 1
}

fn test_rfc7239_forwarded() {
    // 1. Format IPv4 Forwarded element
    var elem4 = wing::ForwardedElement {
        for_node: "192.0.2.60",
        proto:    "https",
        host:     "api.example.com",
        ..
    };
    var fwd_buf: u8[..512] = [];
    wing::format_forwarded_element(elem4, fwd_buf);
    assert(core::contains(fwd_buf[..], "for=192.0.2.60"));
    assert(core::contains(fwd_buf[..], "proto=https"));
    assert(core::contains(fwd_buf[..], "host=api.example.com"));
    print("FORWARDED_IPV4_OK: 1");
    // CHECK: FORWARDED_IPV4_OK: 1

    // 2. Format IPv6 Forwarded element with mandatory double quotes (RFC 7239 §4)
    var elem6 = wing::ForwardedElement {
        by:       "203.0.113.43",
        for_node: "[2001:db8:cafe::17]:4711",
        proto:    "http",
        ..
    };
    var fwd_buf6: u8[..512] = [];
    wing::format_forwarded_element(elem6, fwd_buf6);
    assert(core::contains(fwd_buf6[..], "for=\"[2001:db8:cafe::17]:4711\""));
    assert(core::contains(fwd_buf6[..], "by=203.0.113.43"));
    print("FORWARDED_IPV6_QUOTES_OK: 1");
    // CHECK: FORWARDED_IPV6_QUOTES_OK: 1

    // 3. Append to HeaderMap
    var headers = wing::HeaderMap { .. };
    wing::append_forwarded_header(headers, elem4);
    let h_val = wing::get_header(headers, "Forwarded");
    assert(core::contains(h_val, "for=192.0.2.60"));
    print("FORWARDED_HEADER_APPEND_OK: 1");
    // CHECK: FORWARDED_HEADER_APPEND_OK: 1

    // 4. Parse multi-hop Forwarded header
    let raw_multi = "for=192.0.2.60;proto=http, for=\"[2001:db8::1]\";by=203.0.113.43;host=proxy.net";
    var parsed_elems: wing::ForwardedElement[..8] = [];
    let count = wing::parse_forwarded_header(raw_multi, parsed_elems);
    assert(count == 2);
    assert(parsed_elems[0].for_node[..] == "192.0.2.60");
    assert(parsed_elems[0].proto[..] == "http");
    assert(parsed_elems[1].for_node[..] == "[2001:db8::1]");
    assert(parsed_elems[1].by[..] == "203.0.113.43");
    assert(parsed_elems[1].host[..] == "proxy.net");
    print("FORWARDED_PARSE_MULTI_OK: 1");
    // CHECK: FORWARDED_PARSE_MULTI_OK: 1
}

fn test_rfc_status_codes_and_early_data() {
    // 1. RFC 8470 Section 5.2: 425 Too Early
    assert(rfc::status_phrase(425) == "Too Early");
    assert(rfc::HEADER_EARLY_DATA == "Early-Data");
    let dec_retry = wing::evaluate_early_data_response(425, true);
    match dec_retry {
        RetryOn1Rtt => { print("EARLY_DATA_RETRY_OK: 1"); },
        _ => { assert(false); },
    };
    // CHECK: EARLY_DATA_RETRY_OK: 1

    // 2. RFC 9110 Section 15.5.21: 422 Unprocessable Content
    assert(rfc::status_phrase(422) == "Unprocessable Content");

    // 3. RFC 6585: Additional HTTP Status Codes
    assert(rfc::status_phrase(428) == "Precondition Required");
    assert(rfc::status_phrase(431) == "Request Header Fields Too Large");
    assert(rfc::status_phrase(511) == "Network Authentication Required");

    // 4. RFC 7725: 451 Unavailable For Legal Reasons
    assert(rfc::status_phrase(451) == "Unavailable For Legal Reasons");

    // 5. RFC 6266: Content-Disposition
    assert(rfc::HEADER_CONTENT_DISPOSITION == "Content-Disposition");
    print("STATUS_CODES_AND_HEADERS_OK: 1");
    // CHECK: STATUS_CODES_AND_HEADERS_OK: 1
}

fn run_05_verify_http_problem_and_forwarded() {
    test_rfc9457_problem_details();
    test_rfc7239_forwarded();
    test_rfc_status_codes_and_early_data();
    print("ALL_RFC_VERIFICATIONS_PASSED");
    // CHECK: ALL_RFC_VERIFICATIONS_PASSED
}

// ============================================================================
// 6. verify_smuggling_desync (6/10)
// ============================================================================
// CHECK: === [6/10] verify_smuggling_desync ===

// tests/lit/verify_smuggling_desync.goose
// Verification of HTTP/1.1 Request Smuggling (CL.TE, TE.CL), Desync, and Chunked FSM Defenses.
//

fn parse_chunk_step(buf: const u8[:]) -> i64 {
    var dec = http_internal::new_chunk_fsm_decoder();
    let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, buf);
    match st {
        YieldChunk => {
            if dec.state == http_internal::CHUNK_STATE_IS_CHUNKED && consumed == buf.len {
                return chunk.len;
            }
            return -1;
        },
        Complete => {
            if consumed == buf.len {
                return 0;
            }
            return -1;
        },
        NeedMore => {
            return -1;
        },
        Error => {
            return -2;
        },
    }
}

fn run_06_verify_smuggling_desync() {
    print("=== HTTP1_SMUGGLE_DEFENSES ===");

    // 1. Conflicting TE followed by CL (TE.CL)
    var map1 = wing::HeaderMap { .. };
    let raw_te_cl = "Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n";
    let err1 = wing::parse_headers(raw_te_cl, map1);
    assert(err1 == wing::HeaderParseError.InvalidContentLength);
    assert(!map1.valid);
    print("TE_CL_CONFLICT: REJECTED");

    // 2. Conflicting CL followed by TE (CL.TE)
    var map2 = wing::HeaderMap { .. };
    let raw_cl_te = "Content-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n";
    let err2 = wing::parse_headers(raw_cl_te, map2);
    assert(err2 == wing::HeaderParseError.InvalidContentLength);
    assert(!map2.valid);
    print("CL_TE_CONFLICT: REJECTED");

    // 3. Duplicate differing Content-Length headers (CL.CL)
    var map3 = wing::HeaderMap { .. };
    let raw_diff_cl = "Content-Length: 10\r\nContent-Length: 20\r\n\r\n";
    let err3 = wing::parse_headers(raw_diff_cl, map3);
    assert(err3 == wing::HeaderParseError.InvalidContentLength);
    assert(!map3.valid);
    print("DUP_CL_DIFF: REJECTED");

    // 4. Duplicate IDENTICAL Content-Length headers per RFC 9112 §6.3
    var map4 = wing::HeaderMap { .. };
    let raw_same_cl = "Content-Length: 42\r\nContent-Length: 42\r\n\r\n";
    let err4 = wing::parse_headers(raw_same_cl, map4);
    assert(err4 == wing::HeaderParseError.None);
    assert(map4.valid);
    assert(wing::get_header(map4, "content-length") == "42");
    print("DUP_CL_SAME: ACCEPTED");

    // 5. 64-bit integer overflow in Content-Length (30-digit flood)
    var map5 = wing::HeaderMap { .. };
    let raw_ovf = "Content-Length: 999999999999999999999999999999\r\n\r\n";
    let err5 = wing::parse_headers(raw_ovf, map5);
    assert(err5 == wing::HeaderParseError.InvalidContentLength);
    print("CL_OVERFLOW: REJECTED");

    // 6. obs-fold on Content-Length rejection even in compatibility mode
    var map6 = wing::HeaderMap { .. };
    let raw_fold = "Content-Length: 10\r\n 20\r\n\r\n";
    let err6 = wing::parse_headers(raw_fold, map6, true);
    assert(err6 == wing::HeaderParseError.InvalidContentLength);
    print("CL_OBS_FOLD: REJECTED");

    // 7. Duplicate Transfer-Encoding headers rejection
    var map7 = wing::HeaderMap { .. };
    let raw_dup_te = "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n";
    let err7 = wing::parse_headers(raw_dup_te, map7);
    assert(err7 == wing::HeaderParseError.InvalidContentLength);
    print("DUP_TE_HEADERS: REJECTED");

    // 8. Chunked single-register FSM stream slicing and mutation fuzzing
    let valid_chunk = "B\r\nHello World\r\n";
    assert(wire_kit::verify_split_stream(valid_chunk, -1, 11, parse_chunk_step));
    assert(wire_kit::fuzz_payload(valid_chunk, 200, parse_chunk_step));
    print("CHUNK_SPLIT_AND_FUZZ: PASS");

    // 9. Hex chunk size overflow attack
    var raw_hex_ovf: u8[>..] = [];
    assert(wire_kit::parse_hex("7FFFFFFFFFFFFFFF0D0A", raw_hex_ovf));
    assert(parse_chunk_step(raw_hex_ovf[..]) == -2);
    print("CHUNK_HEX_OVERFLOW: REJECTED");

    // 10. Pipelined stream demarcation rejection of TE.CL smuggling (RFC 9112 §6.1, §6.3)
    var srv_te_cl = wing::new_http_server();
    var out_wire1: u8[..4096] = [];
    let payload_te_cl = "POST /submit HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n0\r\n\r\n";
    let _, _, ok1, _ = wing::handle_connection_wire_pipelined_stream(srv_te_cl, "127.0.0.1", payload_te_cl, 0, out_wire1);
    assert(!ok1);
    assert(find(out_wire1[..], "400 Bad Request") >= 0);
    print("PIPELINE_TE_CL_SMUGGLE: REJECTED");

    // 11. Pipelined stream demarcation rejection of CL.TE smuggling (RFC 9112 §6.1, §6.3)
    var srv_cl_te = wing::new_http_server();
    var out_wire2: u8[..4096] = [];
    let payload_cl_te = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let _, _, ok2, _ = wing::handle_connection_wire_pipelined_stream(srv_cl_te, "127.0.0.1", payload_cl_te, 0, out_wire2);
    assert(!ok2);
    assert(find(out_wire2[..], "400 Bad Request") >= 0);
    print("PIPELINE_CL_TE_SMUGGLE: REJECTED");

    // 12. Pipelined stream demarcation rejection of duplicate differing CL (RFC 9112 §6.3)
    var srv_cl_cl = wing::new_http_server();
    var out_wire3: u8[..4096] = [];
    let payload_cl_cl = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\nContent-Length: 60\r\n\r\nhello";
    let _, _, ok3, _ = wing::handle_connection_wire_pipelined_stream(srv_cl_cl, "127.0.0.1", payload_cl_cl, 0, out_wire3);
    assert(!ok3);
    assert(find(out_wire3[..], "400 Bad Request") >= 0);
    print("PIPELINE_DUP_CL_DIFF: REJECTED");

    // 13. Reverse proxy Content-Length stripping when Transfer-Encoding present (RFC 9112 §6.3)
    var in_proxy_te = wing::HeaderMap { .. };
    wing::append_header(in_proxy_te, "Host", "example.com");
    wing::append_header(in_proxy_te, "Transfer-Encoding", "chunked");
    wing::append_header(in_proxy_te, "Content-Length", "42");
    var out_proxy_te = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.strip_hop_by_hop = false;
    let ok_te_cl = wing::filter_and_forward_headers(in_proxy_te, out_proxy_te, "127.0.0.1", "http", "backend:80", cfg);
    assert(!ok_te_cl);
    assert(!wing::has_header(out_proxy_te, "Content-Length"));
    print("PROXY_TE_CL_STRIP_CL: PASS");

    // 14. Reverse proxy duplicate Content-Length rejection / consolidation (RFC 9112 §6.3)
    var in_p_diff = wing::HeaderMap { .. };
    wing::append_header(in_p_diff, "Host", "example.com");
    wing::append_header(in_p_diff, "Content-Length", "10");
    wing::append_header(in_p_diff, "Content-Length", "20");
    var out_p_diff = wing::HeaderMap { .. };
    let ok_p_diff = wing::filter_and_forward_headers(in_p_diff, out_p_diff, "127.0.0.1", "http", "backend:80", cfg);
    assert(!ok_p_diff);

    var in_p_same = wing::HeaderMap { .. };
    wing::append_header(in_p_same, "Host", "example.com");
    wing::append_header(in_p_same, "Content-Length", "42");
    wing::append_header(in_p_same, "Content-Length", "42");
    var out_p_same = wing::HeaderMap { .. };
    let ok_p_same = wing::filter_and_forward_headers(in_p_same, out_p_same, "127.0.0.1", "http", "backend:80", cfg);
    assert(ok_p_same);
    var p_cl_count: i64 = 0;
    for i in out_p_same.entries.len {
        let entry = out_p_same.entries[i];
        let name = out_p_same.raw_buf[entry.name_begin..entry.name_end];
        if core::eq_ascii_fold(name, "content-length") { p_cl_count++; }
    }
    assert(p_cl_count == 1);
    print("PROXY_DUP_CL_RESOLVED: PASS");

    // 15. Reverse proxy TE/CL smuggling edge variations (RFC 9112 §6.1, §6.3)
    var in_p_ws = wing::HeaderMap { .. };
    wing::append_header(in_p_ws, "Host", "example.com");
    wing::append_header(in_p_ws, "Transfer-Encoding", "   chunked  \t");
    wing::append_header(in_p_ws, "Content-Length", "10");
    var out_p_ws = wing::HeaderMap { .. };
    assert(!wing::filter_and_forward_headers(in_p_ws, out_p_ws, "127.0.0.1", "http", "backend:80", cfg));

    var in_p_mc = wing::HeaderMap { .. };
    wing::append_header(in_p_mc, "Host", "example.com");
    wing::append_header(in_p_mc, "tRaNsFeR-eNcOdInG", "chunked");
    wing::append_header(in_p_mc, "cOnTeNt-LeNgTh", "10");
    var out_p_mc = wing::HeaderMap { .. };
    assert(!wing::filter_and_forward_headers(in_p_mc, out_p_mc, "127.0.0.1", "http", "backend:80", cfg));

    var in_p_mte = wing::HeaderMap { .. };
    wing::append_header(in_p_mte, "Host", "example.com");
    wing::append_header(in_p_mte, "Transfer-Encoding", "chunked");
    wing::append_header(in_p_mte, "Transfer-Encoding", "gzip");
    var out_p_mte = wing::HeaderMap { .. };
    assert(!wing::filter_and_forward_headers(in_p_mte, out_p_mte, "127.0.0.1", "http", "backend:80", cfg));
    print("PROXY_TE_CL_VARIATIONS: REJECTED");
}

// CHECK-LABEL: === HTTP1_SMUGGLE_DEFENSES ===
// CHECK-NEXT: TE_CL_CONFLICT: REJECTED
// CHECK-NEXT: CL_TE_CONFLICT: REJECTED
// CHECK-NEXT: DUP_CL_DIFF: REJECTED
// CHECK-NEXT: DUP_CL_SAME: ACCEPTED
// CHECK-NEXT: CL_OVERFLOW: REJECTED
// CHECK-NEXT: CL_OBS_FOLD: REJECTED
// CHECK-NEXT: DUP_TE_HEADERS: REJECTED
// CHECK-NEXT: CHUNK_SPLIT_AND_FUZZ: PASS
// CHECK-NEXT: CHUNK_HEX_OVERFLOW: REJECTED
// CHECK-NEXT: PIPELINE_TE_CL_SMUGGLE: REJECTED
// CHECK-NEXT: PIPELINE_CL_TE_SMUGGLE: REJECTED
// CHECK-NEXT: PIPELINE_DUP_CL_DIFF: REJECTED
// CHECK-NEXT: PROXY_TE_CL_STRIP_CL: PASS
// CHECK-NEXT: PROXY_DUP_CL_RESOLVED: PASS
// CHECK-NEXT: PROXY_TE_CL_VARIATIONS: REJECTED

// ============================================================================
// 7. verify_slicer_drip (7/10)
// ============================================================================
// CHECK: === [7/10] verify_slicer_drip ===

// tests/lit/verify_slicer_drip.goose
// Chaos slicer and drip ingress verification across HTTP/1 chunked FSM, HTTP/2 framing, gRPC LPM, and QUIC varints.
// Verifies byte-by-byte and 2-byte boundary fragmentation without hang, crash, or state corruption.
//

// 1. Chaos Drip Test 1: HTTP/1.1 Chunked Transfer FSM (RFC 9112 §7.1)
// Ingests chunks byte-by-byte, specifically checking split between \r and \n.
fn test_chunked_fsm_drip() {
    let wire = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    var dec = http_internal::new_chunk_fsm_decoder();
    var assembled: u8[..64] = [];

    var i: i64 = 0;
    while i < wire.len {
        // Drip 1 byte at a time
        let single_byte = wire[i..i + 1];
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, single_byte);
        assert(st != http_internal::ChunkFsmStatus.Error);
        if st == http_internal::ChunkFsmStatus.YieldChunk {
            assembled.append(chunk);
        }
        i += 1;
    }

    assert(assembled[..] == "hello world");
    print("CHUNKED_FSM_DRIP: OK");
}

// 2. Chaos Drip Test 2: HTTP/2 Ingress Socket Drip (RFC 9113 §4.1)
// Ingests partial frames through handle_h2_server_ingress, verifying safe postponement
// until the complete 9-byte header and full payload are assembled in the buffer.
fn test_h2_socket_drip() {
    var client_hpack = h2_internal::DynamicTable { .. };
    var sess = server_internal::new_h2_server_session("localhost");
    var pipeline = wing::ServerPipelineConfig { .. };
    var timer = server_internal::ConnectionTimer { .. };

    // Handshake
    var init_wire: u8[..64] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_hdr = h2_internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    h2_internal::encode_frame_header_to(set_hdr, init_wire);
    var server_out: u8[..1024] = [];
    let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out);
    assert(ok_init);

    // Prepare complete HEADERS frame for stream 1
    var full_req:    u8[..256] = [];
    var hpack_block: u8[..128] = [];
    h2_internal::encode_hpack_field(client_hpack, hpack_block, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_hpack, hpack_block, ":path", "/drip", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_hpack, hpack_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_hpack, hpack_block, ":authority", "example.com", h2_internal::HpackIndexing.Incremental, false);

    let req_hdr = h2_internal::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    h2_internal::encode_frame_header_to(req_hdr, full_req);
    full_req.append(hpack_block[..]);

    // Stage 1: Partial 5 bytes of 9-byte header -> consumed must be 0, ok == true
    server_out.clear();
    let c1, ok1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..5], 1001, server_out);
    assert(ok1);
    assert(c1 == 0);
    assert(server_out.len == 0);

    // Stage 2: Header complete (9 bytes) + partial 3 bytes of payload -> consumed must be 0
    let c2, ok2 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..12], 1002, server_out);
    assert(ok2);
    assert(c2 == 0);
    assert(server_out.len == 0);

    // Stage 3: Full frame arrives -> consumed must be full_req.len, response emitted
    let c3, ok3 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..], 1003, server_out);
    assert(ok3);
    assert(c3 == full_req.len);
    assert(server_out.len > 0);

    print("H2_SOCKET_DRIP: OK");
}

// 3. Chaos Drip Test 3: gRPC Incremental LPM Parser (gRPC HTTP/2 Wire Protocol)
// Streams a 5-byte header + 18-byte payload 1 byte at a time.
fn test_grpc_lpm_drip() {
    var parser = wing::new_grpc_stream_parser(65536);
    let payload = "CHAOS_GRPC_PAYLOAD";

    var full_wire: u8[..64] = [];
    wing::encode_grpc_lpm(payload[..], full_wire, false);
    assert(full_wire.len == 5 + payload.len);

    var msg: u8[..64] = [];
    var is_comp = false;

    // Drip byte by byte up to byte 21 (all must return ready == false)
    for i in (full_wire.len - 1) {
        let ok_feed = wing::feed(parser, full_wire[i..i + 1]);
        assert(ok_feed);
        let ready = wing::next_message(parser, msg, is_comp);
        assert(!ready);
    }

    // Final byte completes the message
    let ok_feed_final = wing::feed(parser, full_wire[full_wire.len - 1..]);
    assert(ok_feed_final);
    let ready_final = wing::next_message(parser, msg, is_comp);
    assert(ready_final);
    assert(msg[..] == "CHAOS_GRPC_PAYLOAD");
    assert(!is_comp);

    print("GRPC_LPM_DRIP: OK");
}

// 4. Chaos Drip Test 4: QUIC Varint Drip & Truncation (RFC 9000 §16)
// Verifies truncated 8-byte, 4-byte, and 2-byte varints reject cleanly without crashing.
fn test_quic_varint_drip() {
    // 8-byte varint for 0x3FFFFFFFFFFFFFFF: prefix 0b11
    let full_8: u8[8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    // Drip 1..7 bytes: all must fail ok == false
    for len in 7 {
        let drip_len = (len + 1) as i64;
        let _, _, ok = quic_internal::quic_decode_varint(full_8[..drip_len], 0);
        assert(!ok);
    }

    // Full 8 bytes succeed
    let val_8, off_8, ok_8 = quic_internal::quic_decode_varint(full_8[..], 0);
    assert(ok_8);
    assert(off_8 == 8);
    assert(val_8 == 0x3FFFFFFFFFFFFFFF);

    print("QUIC_VARINT_DRIP: OK");
}

fn run_07_verify_slicer_drip() {
    test_chunked_fsm_drip();
    test_h2_socket_drip();
    test_grpc_lpm_drip();
    test_quic_varint_drip();
}

// CHECK: CHUNKED_FSM_DRIP: OK
// CHECK-NEXT: H2_SOCKET_DRIP: OK
// CHECK-NEXT: GRPC_LPM_DRIP: OK
// CHECK-NEXT: QUIC_VARINT_DRIP: OK

// ============================================================================
// 8. verify_chaos_slicer (8/10)
// ============================================================================
// CHECK: === [8/10] verify_chaos_slicer ===

fn test_pipe_buffer_reassembly() {
    var pipe = core::new_pipe_buffer();

    let chunks: const u8[:][5] = [
        "GET ",
        "/a",
        "pi/v1/",
        "stream",
        " HTTP/1",
    ];

    for c in chunks {
        let n, err = core::write(pipe, c);
        assert(err == core::IoError.None);
        assert(n == c.len);
    }

    assert(core::readable_len(pipe) == 25);
    var target: u8[64] = [0; 64];
    let n, err = core::read(pipe, target[..25]);
    assert(err == core::IoError.None);
    assert(n == 25);
    assert(target[..25] == "GET /api/v1/stream HTTP/1");
}

fn test_cork_buffer_streaming() {
    var cb = core::new_cork_buffer();
    assert(core::cork_is_empty(cb));

    let err = core::cork_write_exact(cb, "GET /api/v1/stream HTTP/1.1\r\n");
    assert(err == core::IoError.None);
    assert(core::cork_pending(cb) == 29);
    assert(core::cork_as_slice(cb) == "GET /api/v1/stream HTTP/1.1\r\n");
}

fn test_ring_buffer_streaming() {
    var rb = core::new_ring_buffer();
    assert(core::is_empty(rb));

    let w1, err1 = core::write(rb, "GET /api/v1/");
    assert(err1 == core::IoError.None && w1 == 12);

    var tmp1: u8[12] = [0; 12];
    let r1, err_r1 = core::read(rb, tmp1[..]);
    assert(err_r1 == core::IoError.None && r1 == 12);
    assert(tmp1[..] == "GET /api/v1/");

    let w2, err2 = core::write(rb, "stream HTTP/1");
    assert(err2 == core::IoError.None && w2 == 13);

    var tmp2: u8[13] = [0; 13];
    let r2, err_r2 = core::read(rb, tmp2[..]);
    assert(err_r2 == core::IoError.None && r2 == 13);
    assert(tmp2[..] == "stream HTTP/1");
    assert(core::is_empty(rb));
}

fn run_08_verify_chaos_slicer() {
    test_pipe_buffer_reassembly();
    test_cork_buffer_streaming();
    test_ring_buffer_streaming();
    print("CHAOS_SLICER: DRAINED 25 BYTES OK");
}

// CHECK: CHAOS_SLICER: DRAINED 25 BYTES OK

// ============================================================================
// 9. verify_chaos_fuzzing (9/10)
// ============================================================================
// CHECK: === [9/10] verify_chaos_fuzzing ===

// Section 1: HTTP/1 chunked parser wired to wing FSM
fn parse_chunk_size(buf: const u8[:]) -> i64 {
    var dec = http_internal::new_chunk_fsm_decoder();
    let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, buf);
    match st {
        YieldChunk => {
            if dec.state == http_internal::CHUNK_STATE_IS_CHUNKED && consumed == buf.len {
                return chunk.len;
            }
            return -1;
        },
        Complete => {
            if consumed == buf.len {
                return 0;
            }
            return -1;
        },
        NeedMore => {
            return -1;
        },
        Error => {
            return -2;
        },
    }
}

// Section 2: DNS wire question parser wired to wing DNS decoder
fn parse_dns_question(buf: const u8[:]) -> i64 {
    if buf.len < 12 { return -1; }
    let qdcount = core::read_be_u16(buf, 4);
    if qdcount == 0 { return -2; }

    var off: i64 = 12;
    var saw_end = false;
    while off < buf.len {
        let b = buf[off];
        if b == 0 {
            off += 1;
            saw_end = true;
            break;
        }
        if (b & 0xC0) == 0xC0 {
            if off + 2 > buf.len { return -1; }
            off += 2;
            saw_end = true;
            break;
        }
        if (b & 0xC0) != 0 || b > 63 { return -2; }
        let label_len = b as i64;
        off += 1 + label_len;
        if off > buf.len { return -1; }
    }
    if !saw_end { return -1; }

    var decode_off: i64       = 12;
    var name_out:   u8[..256] = [];
    if !dns::decode_name(buf, decode_off, name_out) {
        return -2;
    }
    if buf.len < decode_off + 4 { return -1; }
    let qtype = core::read_be_u16(buf, decode_off);
    let qclass = core::read_be_u16(buf, decode_off + 2);
    if qclass != 1 && qclass != 255 { return -2; }
    return qtype;
}

// Section 3: TLS 1.3 record header parser wired to wing TLS record decoder
fn parse_tls_record_header(buf: const u8[:]) -> i64 {
    if buf.len < 5 { return -1; }
    let _, _, rlen, _, ok = wing::parse_tls_record_header(buf);
    if !ok { return -2; }
    return rlen;
}

// Section 4: WebSocket extended header parser wired to wing WebSocket decoder
fn parse_ws_extended_header(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let opcode = buf[0] & 0x0F;
    if !rfc::is_valid_ws_opcode(opcode) { return -2; }
    let masked = (buf[1] & 0x80) != 0;
    let raw_len = buf[1] & 0x7F;
    var min_hdr: i64 = 2;
    if raw_len == 126 { min_hdr += 2; }
    else if raw_len == 127 { min_hdr += 8; }
    if masked { min_hdr += 4; }
    if buf.len < min_hdr { return -1; }

    let hdr, ok = wing::parse_ws_frame_header(buf);
    if !ok { return -2; }
    return hdr.payload_len as! i64;
}

fn run_09_verify_chaos_fuzzing() {
    var chunk_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("31410d0a30313233343536373839616263646566303132333435363738390d0a", chunk_pkt));
    assert(wire_kit::verify_split_stream(chunk_pkt[..], -1, 26, parse_chunk_size));
    assert(wire_kit::fuzz_payload(chunk_pkt[..], 100, parse_chunk_size));
    print("CHAOS_CHUNKED: OK");

    var dns_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("123401000001000000000000076578616d706c6503636f6d0000010001", dns_pkt));
    assert(wire_kit::verify_split_stream(dns_pkt[..], -1, 1, parse_dns_question));
    assert(wire_kit::fuzz_payload(dns_pkt[..], 100, parse_dns_question));
    print("CHAOS_DNS: OK");

    var tls_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("1703030080", tls_pkt));
    assert(wire_kit::verify_split_stream(tls_pkt[..], -1, 128, parse_tls_record_header));
    assert(wire_kit::fuzz_payload(tls_pkt[..], 100, parse_tls_record_header));
    print("CHAOS_TLS: OK");

    var ws_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("81fe0100a1b2c3d4", ws_pkt));
    assert(wire_kit::verify_split_stream(ws_pkt[..], -1, 256, parse_ws_extended_header));
    assert(wire_kit::fuzz_payload(ws_pkt[..], 100, parse_ws_extended_header));
    print("CHAOS_WS: OK");
}

// CHECK: CHAOS_CHUNKED: OK
// CHECK: CHAOS_DNS: OK
// CHECK: CHAOS_TLS: OK
// CHECK: CHAOS_WS: OK

// ============================================================================
// 10. verify_edge_and_fuzz (10/10)
// ============================================================================
// CHECK: === [10/10] verify_edge_and_fuzz ===

// Wire bridge to HTTP/2 frame header decoder and rule validator
fn decode_h2_header(buf: const u8[:]) -> i64 {
    if buf.len < 9 { return -1; }
    let hdr, err = h2_internal::parse_frame_header(buf, 16384);
    if err != rfc::H2_ERR_NO_ERROR { return -2; }
    if h2_internal::validate_frame_header_rules(hdr) != rfc::H2_ERR_NO_ERROR { return -2; }
    return hdr.length;
}

// Wire bridge to WebSocket frame parser with RFC 6455 bounds checking
fn validate_ws_frame(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let opcode = buf[0] & 0x0F;
    if !rfc::is_valid_ws_opcode(opcode) { return -2; }
    let masked = (buf[1] & 0x80) != 0;
    let raw_len = buf[1] & 0x7F;
    var min_hdr: i64 = 2;
    if raw_len == 126 { min_hdr += 2; }
    else if raw_len == 127 { min_hdr += 8; }
    if masked { min_hdr += 4; }
    if buf.len < min_hdr { return -1; }

    let hdr, ok = wing::parse_ws_frame_header(buf);
    if !ok { return -2; }
    let total: i64 = hdr.header_len + (hdr.payload_len as! i64);
    if buf.len < total { return -1; }
    return hdr.payload_len as! i64;
}

fn run_10_verify_edge_and_fuzz() {
    var h2_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("000008010500000003", h2_pkt));
    assert(wire_kit::verify_split_stream(h2_pkt[..], -1, 8, decode_h2_header));
    assert(wire_kit::fuzz_payload(h2_pkt[..], 100, decode_h2_header));
    print("EDGE_H2_HEADER: OK");

    var ws_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("81850102030468656C6C6F", ws_pkt));
    assert(wire_kit::verify_split_stream(ws_pkt[..], -1, 5, validate_ws_frame));
    assert(wire_kit::fuzz_payload(ws_pkt[..], 100, validate_ws_frame));
    print("EDGE_WS_FRAME: OK");

    var hdr_orig = h2_internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_STREAM | rfc::H2_FLAG_END_HEADERS,
        stream_id:  3,
    };
    var enc_hdr: u8[9] = [0; 9];
    h2_internal::encode_frame_header(hdr_orig, enc_hdr);
    let hdr_dec, err = h2_internal::parse_frame_header(enc_hdr[..]);
    assert(err == rfc::H2_ERR_NO_ERROR);
    assert(hdr_dec.length == 8);
    assert(hdr_dec.frame_type == rfc::H2_FRAME_HEADERS);
    assert(hdr_dec.flags == (rfc::H2_FLAG_END_STREAM | rfc::H2_FLAG_END_HEADERS));
    assert(hdr_dec.stream_id == 3);
    print("EDGE_ROUNDTRIP: OK");
}

// CHECK: EDGE_H2_HEADER: OK
// CHECK: EDGE_WS_FRAME: OK
// CHECK: EDGE_ROUNDTRIP: OK

fn main() {
    print("\n=== [1/10] verify_http1_chunked ===\n");
    run_01_verify_http1_chunked();
    print("\n=== [2/10] verify_sfv_rfc9651 ===\n");
    run_02_verify_sfv_rfc9651();
    print("\n=== [3/10] verify_http_extensions_edge ===\n");
    run_03_verify_http_extensions_edge();
    print("\n=== [4/10] verify_http_incremental ===\n");
    run_04_verify_http_incremental();
    print("\n=== [5/10] verify_http_problem_and_forwarded ===\n");
    run_05_verify_http_problem_and_forwarded();
    print("\n=== [6/10] verify_smuggling_desync ===\n");
    run_06_verify_smuggling_desync();
    print("\n=== [7/10] verify_slicer_drip ===\n");
    run_07_verify_slicer_drip();
    print("\n=== [8/10] verify_chaos_slicer ===\n");
    run_08_verify_chaos_slicer();
    print("\n=== [9/10] verify_chaos_fuzzing ===\n");
    run_09_verify_chaos_fuzzing();
    print("\n=== [10/10] verify_edge_and_fuzz ===\n");
    run_10_verify_edge_and_fuzz();
}
