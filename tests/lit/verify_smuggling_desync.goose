// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_smuggling_desync.goose
// Verification of HTTP/1.1 Request Smuggling (CL.TE, TE.CL), Desync, and Chunked FSM Defenses.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn parse_chunk_step(buf: const u8[:]) -> i64 {
    var dec = internal::new_chunk_fsm_decoder();
    let st, consumed, chunk = internal::chunk_fsm_feed(dec, buf);
    match st {
        YieldChunk => {
            if dec.state == internal::CHUNK_STATE_IS_CHUNKED && consumed == buf.len {
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

fn main() {
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
    assert(core::index_of_slice(out_wire1[..], "400 Bad Request") >= 0);
    print("PIPELINE_TE_CL_SMUGGLE: REJECTED");

    // 11. Pipelined stream demarcation rejection of CL.TE smuggling (RFC 9112 §6.1, §6.3)
    var srv_cl_te = wing::new_http_server();
    var out_wire2: u8[..4096] = [];
    let payload_cl_te = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let _, _, ok2, _ = wing::handle_connection_wire_pipelined_stream(srv_cl_te, "127.0.0.1", payload_cl_te, 0, out_wire2);
    assert(!ok2);
    assert(core::index_of_slice(out_wire2[..], "400 Bad Request") >= 0);
    print("PIPELINE_CL_TE_SMUGGLE: REJECTED");

    // 12. Pipelined stream demarcation rejection of duplicate differing CL (RFC 9112 §6.3)
    var srv_cl_cl = wing::new_http_server();
    var out_wire3: u8[..4096] = [];
    let payload_cl_cl = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\nContent-Length: 60\r\n\r\nhello";
    let _, _, ok3, _ = wing::handle_connection_wire_pipelined_stream(srv_cl_cl, "127.0.0.1", payload_cl_cl, 0, out_wire3);
    assert(!ok3);
    assert(core::index_of_slice(out_wire3[..], "400 Bad Request") >= 0);
    print("PIPELINE_DUP_CL_DIFF: REJECTED");

    // 13. Reverse proxy Content-Length stripping when Transfer-Encoding present (RFC 9112 §6.3)
    var in_proxy_te = wing::HeaderMap { .. };
    wing::append_header(in_proxy_te, "Host", "example.com");
    wing::append_header(in_proxy_te, "Transfer-Encoding", "chunked");
    wing::append_header(in_proxy_te, "Content-Length", "42");
    var out_proxy_te = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.strip_hop_by_hop = false;
    wing::filter_and_forward_headers(in_proxy_te, out_proxy_te, "127.0.0.1", "http", "backend:80", cfg);
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
