// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_wire_and_e2e
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_cross_protocol_differential (1/12)
// ============================================================================
// CHECK: === [1/12] verify_cross_protocol_differential ===

// tests/lit/verify_cross_protocol_differential.goose
// Verification of Cross-Protocol Differential Defenses:
// 1. HTTP/1.1 chunking desync FSM (hex overflow, bare LF, quoted-pair extensions).
// 2. Request smuggling & framing conflicts (CL.TE, TE.CL, dup CL, dup Host, null bytes).
// 3. Layer 7 Reverse Proxy hop-by-hop stripping, connection tokens, and XFF chaining.
// 4. HTTP/2 CONTINUATION flood & interleaving violations (RFC 9113 §4.3 & §6.10, CVE-2024-27983).
// 5. HTTP/2 Rapid Reset & Ping flood DoS defenses (CVE-2023-44487).
// 6. HTTP/2 pseudo-header invariants and connection-specific header bans (RFC 9113 §8.2.2 & §8.3).
// 7. Cross-protocol differential fuzzing mutation harness.
//

fn parse_wire_chunk_step(buf: const u8[:]) -> i64 {
    var dec = internal::new_chunk_fsm_decoder();
    let st, _, chunk = internal::chunk_fsm_feed(dec, buf);
    if st == internal::ChunkFsmStatus.YieldChunk {
        return chunk.len;
    }
    if st == internal::ChunkFsmStatus.Complete {
        return 0;
    }
    if st == internal::ChunkFsmStatus.NeedMore {
        return 1;
    }
    return 2;
}

fn parse_wire_h2_step(buf: const u8[:]) -> i64 {
    if buf.len < 9 {
        return 0;
    }
    let hdr, err = internal::parse_frame_header(buf);
    if err != rfc::H2_ERR_NO_ERROR {
        return 1;
    }
    return (hdr.stream_id & 0x7FFFFFFF) as i64;
}

fn test_h1_chunking_desync_fsm() {
    // 1. Hex chunk size integer overflow attack (RFC 9112 Section 7.1)
    var dec_ovf = internal::new_chunk_fsm_decoder();
    var hex_ovf_raw: u8[>..] = [];
    assert(wire_kit::parse_hex("7FFFFFFFFFFFFFFF0D0A", hex_ovf_raw));
    let st_ovf, _, _ = internal::chunk_fsm_feed(dec_ovf, hex_ovf_raw[..]);
    assert(st_ovf == internal::ChunkFsmStatus.Error);
    print("H1_CHUNK_OVERFLOW: REJECTED");

    // 2. Bare LF in chunk size (CVE-2023-45287)
    var dec_lf = internal::new_chunk_fsm_decoder();
    let st_lf, _, _ = internal::chunk_fsm_feed(dec_lf, "5\nhello\r\n");
    assert(st_lf == internal::ChunkFsmStatus.Error);
    print("H1_CHUNK_BARE_LF: REJECTED");

    // 3. Bad whitespace before CRLF in chunk size without extension (RFC 9112 §7.1.1)
    var dec_bws = internal::new_chunk_fsm_decoder();
    let st_bws, _, _ = internal::chunk_fsm_feed(dec_bws, "5 \r\nhello\r\n");
    assert(st_bws == internal::ChunkFsmStatus.Error);
    print("H1_CHUNK_BWS_CRLF: REJECTED");

    // 4. Chunk extension with quoted-pair escaping
    var dec_ext = internal::new_chunk_fsm_decoder();
    let ext_raw = "5;desc=\"hello \\\"world\\\"\"\r\nhello\r\n0\r\n\r\n";
    let st_ext, cons_ext, chunk_ext = internal::chunk_fsm_feed(dec_ext, ext_raw);
    assert(st_ext == internal::ChunkFsmStatus.YieldChunk);
    assert(chunk_ext == "hello");
    let st_ext2, _, _ = internal::chunk_fsm_feed(dec_ext, ext_raw[cons_ext..]);
    assert(st_ext2 == internal::ChunkFsmStatus.Complete);
    print("H1_CHUNK_QUOTED_EXT: OK");

    // 5. Unclosed quoted string CRLF injection in chunk extension
    var dec_inj = internal::new_chunk_fsm_decoder();
    let inj_raw = "5;ext=\"unclosed\r\n";
    let st_inj, _, _ = internal::chunk_fsm_feed(dec_inj, inj_raw);
    assert(st_inj == internal::ChunkFsmStatus.Error);
    print("H1_CHUNK_CRLF_INJECT: REJECTED");

    // 6. Incomplete chunk header boundary (NeedMore)
    var dec_part = internal::new_chunk_fsm_decoder();
    let part_raw = "A\r";
    let st_part, _, _ = internal::chunk_fsm_feed(dec_part, part_raw);
    assert(st_part == internal::ChunkFsmStatus.NeedMore);
    print("H1_CHUNK_PARTIAL: NEED_MORE");
}

fn test_smuggling_and_framing_conflicts() {
    // 1. CL.TE conflict
    var map_cl_te = wing::HeaderMap { .. };
    let err_cl_te = wing::parse_headers("Content-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n", map_cl_te);
    assert(err_cl_te == wing::HeaderParseError.InvalidContentLength);
    assert(!map_cl_te.valid);
    print("SMUGGLE_CL_TE_CONFLICT: REJECTED");

    // 2. TE.CL conflict
    var map_te_cl = wing::HeaderMap { .. };
    let err_te_cl = wing::parse_headers("Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n", map_te_cl);
    assert(err_te_cl == wing::HeaderParseError.InvalidContentLength);
    assert(!map_te_cl.valid);
    print("SMUGGLE_TE_CL_CONFLICT: REJECTED");

    // 3. Duplicate differing Content-Length headers
    var map_dup_diff = wing::HeaderMap { .. };
    let err_dup_diff = wing::parse_headers("Content-Length: 10\r\nContent-Length: 20\r\n\r\n", map_dup_diff);
    assert(err_dup_diff == wing::HeaderParseError.InvalidContentLength);
    assert(!map_dup_diff.valid);
    print("SMUGGLE_DUP_CL_DIFF: REJECTED");

    // 4. Duplicate identical Content-Length headers (RFC 9112 §6.3)
    var map_dup_same = wing::HeaderMap { .. };
    let err_dup_same = wing::parse_headers("Content-Length: 42\r\nContent-Length: 42\r\n\r\n", map_dup_same);
    assert(err_dup_same == wing::HeaderParseError.None);
    assert(map_dup_same.valid);
    print("SMUGGLE_DUP_CL_SAME: ACCEPTED");

    // 5. Duplicate Host header rejection (RFC 9112 §7.2)
    var map_dup_host = wing::HeaderMap { .. };
    let err_dup_host = wing::parse_headers("Host: a.example.com\r\nHost: b.example.com\r\n\r\n", map_dup_host);
    assert(err_dup_host == wing::HeaderParseError.InvalidHeaderName);
    assert(!map_dup_host.valid);
    print("SMUGGLE_DUP_HOST: REJECTED");

    // 6. Host header with forbidden characters (@ userinfo)
    var map_bad_host = wing::HeaderMap { .. };
    let err_bad_host = wing::parse_headers("Host: admin@example.com\r\n\r\n", map_bad_host);
    assert(err_bad_host == wing::HeaderParseError.InvalidHeaderValue);
    assert(!map_bad_host.valid);
    print("SMUGGLE_HOST_FORBIDDEN_CHARS: REJECTED");

    // 7. Embedded null-byte injection rejection
    var map_null = wing::HeaderMap { .. };
    var null_raw: u8[>..] = [];
    null_raw.append("Host: example.com");
    null_raw.push(0x00);
    null_raw.append("\r\n\r\n");
    let err_null = wing::parse_headers(null_raw[..], map_null);
    assert(err_null == wing::HeaderParseError.EmbeddedNull);
    assert(!map_null.valid);
    print("SMUGGLE_NULL_BYTE: REJECTED");

    // 8. Obsolete line folding rejection
    var map_fold = wing::HeaderMap { .. };
    let err_fold = wing::parse_headers("Host: example.com\r\n folded: val\r\n\r\n", map_fold, false);
    assert(err_fold == wing::HeaderParseError.ObsFoldForbidden);
    assert(!map_fold.valid);
    print("SMUGGLE_OBS_FOLD: REJECTED");
}

fn test_reverse_proxy_hop_by_hop_sanitization() {
    var in_map = wing::HeaderMap { .. };
    wing::append_header(in_map, "Host", "public.example.com");
    wing::append_header(in_map, "Connection", "close, X-Internal-Token");
    wing::append_header(in_map, "Keep-Alive", "timeout=5");
    wing::append_header(in_map, "Transfer-Encoding", "chunked");
    wing::append_header(in_map, "Upgrade", "websocket");
    wing::append_header(in_map, "X-Internal-Token", "secret-payload");
    wing::append_header(in_map, "TE", "trailers");
    wing::append_header(in_map, "X-Forwarded-For", "198.51.100.1");

    var out_map = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.preserve_host = false;
    cfg.trust_incoming_xff = true;
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-chaos");

    wing::filter_and_forward_headers(
        in_map,
        out_map,
        "203.0.113.50",
        "https",
        "internal.backend:8080",
        cfg,
    );

    let h_conn = wing::get_header(out_map, "Connection");
    let h_ka = wing::get_header(out_map, "Keep-Alive");
    let h_te = wing::get_header(out_map, "Transfer-Encoding");
    let h_upg = wing::get_header(out_map, "Upgrade");
    assert(h_conn.len == 0 && h_ka.len == 0 && h_te.len == 0 && h_upg.len == 0);
    print("PROXY_HOP_BY_HOP_STRIPPED: OK");

    let h_token = wing::get_header(out_map, "X-Internal-Token");
    assert(h_token.len == 0);
    print("PROXY_CUSTOM_TOKEN_STRIPPED: OK");

    let h_trailers = wing::get_header(out_map, "TE");
    assert(h_trailers == "trailers");
    print("PROXY_TE_TRAILERS_PRESERVED: OK");

    let h_xff = wing::get_header(out_map, "X-Forwarded-For");
    assert(h_xff == "198.51.100.1, 203.0.113.50");
    print("PROXY_XFF_CHAINED: OK");

    let h_via = wing::get_header(out_map, "Via");
    assert(h_via == "1.1 wing-chaos");
    print("PROXY_VIA_INJECTED: OK");
}

fn test_h2_continuation_flood_and_interleaving() {
    var conn = internal::new_h2_connection(0);

    // 1. Initial HEADERS frame on stream 1 without END_HEADERS
    let h_hdr = internal::FrameHeader {
        length:     128,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      0x0,
        stream_id:  1,
    };
    let err0 = internal::on_ingress_frame_header(conn, h_hdr, 0);
    assert(err0 == rfc::H2_ERR_NO_ERROR);
    assert(conn.continuation_stream_id == 1);
    print("H2_EXPECT_CONTINUATION_STATE: OK");

    // 2. Interleaved PING frame on stream 0 -> ProtocolError
    let ping_hdr = internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      0x0,
        stream_id:  0,
    };
    let err_ping = internal::on_ingress_frame_header(conn, ping_hdr, 0);
    assert(err_ping == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_INTERLEAVED_PING_BAN: PROTOCOL_ERROR");

    // 3. Reset connection: Interleaved DATA frame on stream 1 -> ProtocolError
    var conn_data = internal::new_h2_connection(0);
    let _ = internal::on_ingress_frame_header(conn_data, h_hdr, 0);
    let data_hdr = internal::FrameHeader {
        length:     64,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      0x0,
        stream_id:  1,
    };
    let err_data = internal::on_ingress_frame_header(conn_data, data_hdr, 0);
    assert(err_data == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_INTERLEAVED_DATA_BAN: PROTOCOL_ERROR");

    // 4. Reset connection: CONTINUATION on wrong stream ID (stream 3 instead of 1) -> ProtocolError
    var conn_mismatch = internal::new_h2_connection(0);
    let _ = internal::on_ingress_frame_header(conn_mismatch, h_hdr, 0);
    let cont_bad_sid = internal::FrameHeader {
        length:     64,
        frame_type: rfc::H2_FRAME_CONTINUATION,
        flags:      0x0,
        stream_id:  3,
    };
    let err_bad_sid = internal::on_ingress_frame_header(conn_mismatch, cont_bad_sid, 0);
    assert(err_bad_sid == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_MISMATCHED_STREAM_BAN: PROTOCOL_ERROR");

    // 5. Unsolicited CONTINUATION frame when state is Idle -> ProtocolError
    var conn_idle = internal::new_h2_connection(0);
    let cont_unsolicited = internal::FrameHeader {
        length:     64,
        frame_type: rfc::H2_FRAME_CONTINUATION,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_unsolicited = internal::on_ingress_frame_header(conn_idle, cont_unsolicited, 0);
    assert(err_unsolicited == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_UNSOLICITED_CONTINUATION_BAN: PROTOCOL_ERROR");

    // 6. CONTINUATION flood DoS (CVE-2024-27983): Send 16 allowed, 17th triggers EnhanceYourCalm
    var conn_flood = internal::new_h2_connection(0);
    let _ = internal::on_ingress_frame_header(conn_flood, h_hdr, 0);
    for _ in 16 {
        let cont_ok = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      0x0,
            stream_id:  1,
        };
        let st_ok = internal::on_ingress_frame_header(conn_flood, cont_ok, 0);
        assert(st_ok == rfc::H2_ERR_NO_ERROR);
    }
    let cont_17th = internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_CONTINUATION,
        flags:      0x0,
        stream_id:  1,
    };
    let err_flood = internal::on_ingress_frame_header(conn_flood, cont_17th, 0);
    assert(err_flood == rfc::H2_ERR_ENHANCE_YOUR_CALM);
    print("H2_CONTINUATION_FLOOD_LIMIT: ENHANCE_YOUR_CALM");

    // 7. Cumulative header block size DoS limit (> 8192 bytes)
    var conn_size = internal::new_h2_connection(0);
    let big_h_hdr = internal::FrameHeader {
        length:     8000,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      0x0,
        stream_id:  1,
    };
    let _ = internal::on_ingress_frame_header(conn_size, big_h_hdr, 0);
    let big_cont_hdr = internal::FrameHeader {
        length:     500,
        frame_type: rfc::H2_FRAME_CONTINUATION,
        flags:      0x0,
        stream_id:  1,
    };
    let err_size = internal::on_ingress_frame_header(conn_size, big_cont_hdr, 0);
    assert(err_size == rfc::H2_ERR_ENHANCE_YOUR_CALM);
    print("H2_CUMULATIVE_BLOCK_SIZE_LIMIT: ENHANCE_YOUR_CALM");
}

fn test_h2_dos_and_stream_parity() {
    // 1. Rapid Reset DoS (CVE-2023-44487): 100 allowed, 101st triggers EnhanceYourCalm
    var conn_rr = internal::new_h2_connection(0);
    conn_rr.reset_limiter = internal::new_h2_token_bucket(100, 33, 0);
    conn_rr.last_peer_stream_id = 1;
    for _ in 100 {
        let rst_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_RST_STREAM,
            flags:      0x0,
            stream_id:  1,
        };
        let st_rst = internal::on_ingress_frame_header(conn_rr, rst_hdr, 0);
        assert(st_rst == rfc::H2_ERR_NO_ERROR);
    }
    let rst_101 = internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      0x0,
        stream_id:  1,
    };
    let err_rr = internal::on_ingress_frame_header(conn_rr, rst_101, 0);
    assert(err_rr == rfc::H2_ERR_ENHANCE_YOUR_CALM);
    print("H2_RAPID_RESET_DEFENSE: ENHANCE_YOUR_CALM");

    // 2. Ping flood DoS: 64 allowed, 65th triggers EnhanceYourCalm
    var conn_ping = internal::new_h2_connection(0);
    for _ in 64 {
        let ping_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0x0,
            stream_id:  0,
        };
        let st_p = internal::on_ingress_frame_header(conn_ping, ping_hdr, 0);
        assert(st_p == rfc::H2_ERR_NO_ERROR);
    }
    let ping_65 = internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      0x0,
        stream_id:  0,
    };
    let err_ping_flood = internal::on_ingress_frame_header(conn_ping, ping_65, 0);
    assert(err_ping_flood == rfc::H2_ERR_ENHANCE_YOUR_CALM);
    print("H2_PING_FLOOD_DEFENSE: ENHANCE_YOUR_CALM");

    // 3. Client stream parity: Client HEADERS on even stream ID (stream 2) -> ProtocolError
    var conn_parity = internal::new_h2_connection(0);
    let even_hdr = internal::FrameHeader {
        length:     32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  2,
    };
    let err_parity = internal::on_ingress_frame_header(conn_parity, even_hdr, 0);
    assert(err_parity == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_EVEN_STREAM_ID_BAN: PROTOCOL_ERROR");
}

fn test_h2_pseudo_header_invariants() {
    // 1. Pseudo-header after regular header (RFC 9113 §8.3)
    var pseudo1 = internal::H2PseudoHeaders { .. };
    var list1 = wing::HeaderMap { .. };
    pseudo1.has_regular_header = true;
    let err_order = internal::validate_header_ordering_and_rules(pseudo1, list1, ":method", "GET");
    assert(err_order == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_PSEUDO_ORDERING_INVARIANT: PROTOCOL_ERROR");

    // 2. Duplicate pseudo-header
    var pseudo2 = internal::H2PseudoHeaders { .. };
    var list2 = wing::HeaderMap { .. };
    let _ = internal::validate_header_ordering_and_rules(pseudo2, list2, ":method", "GET");
    let err_dup = internal::validate_header_ordering_and_rules(pseudo2, list2, ":method", "POST");
    assert(err_dup == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_DUPLICATE_PSEUDO_BAN: PROTOCOL_ERROR");

    // 3. Undefined pseudo-header
    var pseudo3 = internal::H2PseudoHeaders { .. };
    var list3 = wing::HeaderMap { .. };
    let err_undef = internal::validate_header_ordering_and_rules(pseudo3, list3, ":custom", "val");
    assert(err_undef == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_UNDEFINED_PSEUDO_BAN: PROTOCOL_ERROR");

    // 4. Forbidden connection-specific headers in HTTP/2 (RFC 9113 §8.2.2)
    var pseudo4 = internal::H2PseudoHeaders { .. };
    var list4 = wing::HeaderMap { .. };
    let err_conn = internal::validate_header_ordering_and_rules(pseudo4, list4, "connection", "close");
    assert(err_conn == rfc::H2_ERR_PROTOCOL_ERROR);
    let err_te = internal::validate_header_ordering_and_rules(pseudo4, list4, "transfer-encoding", "chunked");
    assert(err_te == rfc::H2_ERR_PROTOCOL_ERROR);
    let err_upg = internal::validate_header_ordering_and_rules(pseudo4, list4, "upgrade", "websocket");
    assert(err_upg == rfc::H2_ERR_PROTOCOL_ERROR);
    let err_ka = internal::validate_header_ordering_and_rules(pseudo4, list4, "keep-alive", "timeout=5");
    assert(err_ka == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_FORBIDDEN_CONNECTION_HEADERS: PROTOCOL_ERROR");

    // 5. TE header with disallowed value
    var pseudo5 = internal::H2PseudoHeaders { .. };
    var list5 = wing::HeaderMap { .. };
    let err_te_val = internal::validate_header_ordering_and_rules(pseudo5, list5, "te", "gzip");
    assert(err_te_val == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_DISALLOWED_TE_VALUE: PROTOCOL_ERROR");

    // 6. TE header with allowed 'trailers'
    var pseudo6 = internal::H2PseudoHeaders { .. };
    var list6 = wing::HeaderMap { .. };
    let ok_te_val = internal::validate_header_ordering_and_rules(pseudo6, list6, "te", "trailers");
    assert(ok_te_val == rfc::H2_ERR_NO_ERROR);
    print("H2_ALLOWED_TE_TRAILERS: OK");

    // 7. :authority forbidden characters (@ and /)
    var pseudo7 = internal::H2PseudoHeaders { .. };
    var list7 = wing::HeaderMap { .. };
    let err_auth_at = internal::validate_header_ordering_and_rules(pseudo7, list7, ":authority", "admin@example.com");
    assert(err_auth_at == rfc::H2_ERR_PROTOCOL_ERROR);
    let err_auth_slash = internal::validate_header_ordering_and_rules(pseudo7, list7, ":authority", "example.com/api");
    assert(err_auth_slash == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_AUTHORITY_FORBIDDEN_CHARS: PROTOCOL_ERROR");

    // 8. :authority vs Host mismatch
    var pseudo8 = internal::H2PseudoHeaders { .. };
    var list8 = wing::HeaderMap { .. };
    let _ = internal::validate_header_ordering_and_rules(pseudo8, list8, ":authority", "example.com");
    let err_mismatch = internal::validate_header_ordering_and_rules(pseudo8, list8, "host", "attacker.com");
    assert(err_mismatch == rfc::H2_ERR_PROTOCOL_ERROR);
    print("H2_AUTHORITY_HOST_MISMATCH: PROTOCOL_ERROR");
}

fn test_differential_fuzzing_harness() {
    // 1. Chunked wire payload mutation fuzzing
    let chunk_seed = "B\r\nHello World\r\n0\r\n\r\n";
    assert(wire_kit::fuzz_payload(chunk_seed, 100, parse_wire_chunk_step));
    print("DIFFERENTIAL_CHUNK_FUZZ: PASS");

    // 2. HTTP/2 frame header wire mutation fuzzing
    var h2_seed: u8[>..] = [];
    assert(wire_kit::parse_hex("00000409040000000101020304", h2_seed));
    assert(wire_kit::fuzz_payload(h2_seed[..], 100, parse_wire_h2_step));
    print("DIFFERENTIAL_H2_FUZZ: PASS");
}

fn run_01_verify_cross_protocol_differential() {
    print("=== CROSS_PROTOCOL_DIFFERENTIAL_VERIFICATION ===");
    test_h1_chunking_desync_fsm();
    test_smuggling_and_framing_conflicts();
    test_reverse_proxy_hop_by_hop_sanitization();
    test_h2_continuation_flood_and_interleaving();
    test_h2_dos_and_stream_parity();
    test_h2_pseudo_header_invariants();
    test_differential_fuzzing_harness();
    print("=== ALL_CROSS_PROTOCOL_TESTS_PASS ===");
}

// CHECK-LABEL: === CROSS_PROTOCOL_DIFFERENTIAL_VERIFICATION ===
// CHECK-NEXT: H1_CHUNK_OVERFLOW: REJECTED
// CHECK-NEXT: H1_CHUNK_BARE_LF: REJECTED
// CHECK-NEXT: H1_CHUNK_BWS_CRLF: REJECTED
// CHECK-NEXT: H1_CHUNK_QUOTED_EXT: OK
// CHECK-NEXT: H1_CHUNK_CRLF_INJECT: REJECTED
// CHECK-NEXT: H1_CHUNK_PARTIAL: NEED_MORE
// CHECK-NEXT: SMUGGLE_CL_TE_CONFLICT: REJECTED
// CHECK-NEXT: SMUGGLE_TE_CL_CONFLICT: REJECTED
// CHECK-NEXT: SMUGGLE_DUP_CL_DIFF: REJECTED
// CHECK-NEXT: SMUGGLE_DUP_CL_SAME: ACCEPTED
// CHECK-NEXT: SMUGGLE_DUP_HOST: REJECTED
// CHECK-NEXT: SMUGGLE_HOST_FORBIDDEN_CHARS: REJECTED
// CHECK-NEXT: SMUGGLE_NULL_BYTE: REJECTED
// CHECK-NEXT: SMUGGLE_OBS_FOLD: REJECTED
// CHECK-NEXT: PROXY_HOP_BY_HOP_STRIPPED: OK
// CHECK-NEXT: PROXY_CUSTOM_TOKEN_STRIPPED: OK
// CHECK-NEXT: PROXY_TE_TRAILERS_PRESERVED: OK
// CHECK-NEXT: PROXY_XFF_CHAINED: OK
// CHECK-NEXT: PROXY_VIA_INJECTED: OK
// CHECK-NEXT: H2_EXPECT_CONTINUATION_STATE: OK
// CHECK-NEXT: H2_INTERLEAVED_PING_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_INTERLEAVED_DATA_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_MISMATCHED_STREAM_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_UNSOLICITED_CONTINUATION_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_CONTINUATION_FLOOD_LIMIT: ENHANCE_YOUR_CALM
// CHECK-NEXT: H2_CUMULATIVE_BLOCK_SIZE_LIMIT: ENHANCE_YOUR_CALM
// CHECK-NEXT: H2_RAPID_RESET_DEFENSE: ENHANCE_YOUR_CALM
// CHECK-NEXT: H2_PING_FLOOD_DEFENSE: ENHANCE_YOUR_CALM
// CHECK-NEXT: H2_EVEN_STREAM_ID_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_PSEUDO_ORDERING_INVARIANT: PROTOCOL_ERROR
// CHECK-NEXT: H2_DUPLICATE_PSEUDO_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_UNDEFINED_PSEUDO_BAN: PROTOCOL_ERROR
// CHECK-NEXT: H2_FORBIDDEN_CONNECTION_HEADERS: PROTOCOL_ERROR
// CHECK-NEXT: H2_DISALLOWED_TE_VALUE: PROTOCOL_ERROR
// CHECK-NEXT: H2_ALLOWED_TE_TRAILERS: OK
// CHECK-NEXT: H2_AUTHORITY_FORBIDDEN_CHARS: PROTOCOL_ERROR
// CHECK-NEXT: H2_AUTHORITY_HOST_MISMATCH: PROTOCOL_ERROR
// CHECK-NEXT: DIFFERENTIAL_CHUNK_FUZZ: PASS
// CHECK-NEXT: DIFFERENTIAL_H2_FUZZ: PASS
// CHECK-NEXT: === ALL_CROSS_PROTOCOL_TESTS_PASS ===

// ============================================================================
// 2. verify_live_e2e_workflows (2/12)
// ============================================================================
// CHECK: === [2/12] verify_live_e2e_workflows ===

// End-to-End Live Socket Verification Suite for High-Level Protocol Workflows:
// 1. Live SOCKS5 (RFC 1928/1929) & HTTP CONNECT Proxy Tunnels (`wing::Client` -> Proxy -> `wing::HttpServer`).
// 2. Live 401 Digest SHA-256 (RFC 7616) & Basic Auth (RFC 7617) Challenge-Response + Cookie Jar Persistence.
// 3. Live RFC 9111 HTTP Cache (`200 OK` + `ETag` -> Fresh Hit -> TTL Expiry -> `If-None-Match` -> `304 Not Modified`).
// 4. Live Native Client<->Server WebSocket (RFC 6455 HTTP/1.1 + RFC 8441 HTTP/2 Extended CONNECT) & W3C SSE (`text/event-stream`).
// 5. Live ReverseProxy + LoadBalancer (`execute_proxy_exchange`) with Dead-Target Failover & `X-Forwarded-For`/`Via`.

var g_e2e_client: wing::Client       = wing::Client { .. };
var g_e2e_proxy:  wing::ReverseProxy = wing::ReverseProxy { .. };
var g_e2e_pool:   wing::StreamPool   = wing::StreamPool { .. };

var g_reval_hits: i32 = 0;

fn find_subslice(haystack: const u8[:], needle: const u8[:]) -> i64 {
    guard needle.len > 0 && haystack.len >= needle.len else { return -1; }
    let limit = haystack.len - needle.len + 1;
    for i in limit {
        if haystack[i..i + needle.len] == needle {
            return i;
        }
    }
    return -1;
}

// ---- Server Route Handlers & Live Socket Accept Helper ---------------------

fn handle_tunnel_origin(req: const wing::Request&, res: wing::Response&) {
    // Verify Proxy-Authorization was stripped before reaching origin (Seam 19)
    assert(!req.has_header("proxy-authorization"));
    assert(!req.has_header("proxy-connection"));
    res.status_code = 200;
    res.set_header("X-Origin-Reached", "yes");
    res.body.append("TUNNEL_ORIGIN_OK:");
    res.body.append(req.url[..]);
}

fn handle_digest_protected(req: const wing::Request&, res: wing::Response&) {
    let auth = req.header("authorization");
    if auth.len == 0 || !core::starts_with_fold(auth, "Digest ") {
        res.status_code = 401;
        res.set_header(
            "WWW-Authenticate",
            "Digest realm=\"wing-api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=SHA-256, opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        );
        res.set_header("Set-Cookie", "auth_step=challenged; Path=/");
        res.body.append("UNAUTHORIZED");
        return;
    }
    // Verify client sent the cookie from the 401 challenge AND valid SHA-256 Digest response
    let cookie_hdr = req.header("cookie");
    assert(find_subslice(cookie_hdr, "auth_step=challenged") >= 0);
    assert(find_subslice(auth, "username=\"admin\"") >= 0);
    assert(find_subslice(auth, "realm=\"wing-api\"") >= 0);
    assert(find_subslice(auth, "algorithm=SHA-256") >= 0);
    assert(find_subslice(auth, "uri=\"/digest-protected\"") >= 0);
    res.status_code = 200;
    res.body.append("DIGEST_AUTH_OK");
}

fn handle_cacheable_resource(req: const wing::Request&, res: wing::Response&) {
    let inm = req.header("if-none-match");
    if inm == "\"v42\"" {
        g_reval_hits += 1;
        res.status_code = 304;
        res.set_header("ETag", "\"v42\"");
        res.set_header("Cache-Control", "max-age=60");
        res.set_header("X-Cache-Freshened", "true");
        return;
    }
    res.status_code = 200;
    res.set_header("ETag", "\"v42\"");
    res.set_header("Cache-Control", "max-age=10");
    res.set_header("X-Cache-Freshened", "false");
    res.body.append("CACHED_LIVE_PAYLOAD_V42");
}

fn handle_sse_stream(req: const wing::Request&, res: wing::Response&) {
    wing::init_response(res);
    let last_id = req.header("last-event-id");
    if last_id == "ev-2" {
        wing::sse_format_event(res.body, "resumed", "after-ev-2", "ev-3", 0);
        return;
    }
    wing::sse_format_event(res.body, "tick", "first-line\nsecond-line", "ev-1", 1500);
    wing::sse_format_event(res.body, "message", "final-item", "ev-2", 0);
}

fn handle_proxy_backend(req: const wing::Request&, res: wing::Response&) {
    let xff = req.header("x-forwarded-for");
    let via = req.header("via");
    assert(xff == "198.51.100.77");
    assert(find_subslice(via, "wing") >= 0);
    assert(!req.has_header("x-secret-hop"));
    res.status_code = 200;
    res.set_header("X-Backend-Handled", "true");
    res.body.append("UPSTREAM_LIVE_OK");
}

fn accept_and_serve_one_e2e(lfd: i64) -> bool {
    let sfd = wing::tcp_accept(lfd, 200);
    guard sfd > 0 else { return false; }
    var rx_buf: u8[..4096] = [];
    let n_rx = wing::tcp_recv(sfd, rx_buf, 4096, 200);
    guard n_rx > 0 else {
        wing::tcp_close(sfd);
        return false;
    }
    var req = wing::Request { .. };
    let ok_p, _ = wing::parse_http1_wire_request(rx_buf[..n_rx], req);
    guard ok_p else {
        wing::tcp_close(sfd);
        return false;
    }
    var res = wing::Response { status_code: 404, .. };
    if req.url[..] == "/tunnel-check" {
        handle_tunnel_origin(req, res);
    } else if req.url[..] == "/digest-protected" {
        handle_digest_protected(req, res);
    } else if req.url[..] == "/cache-item" {
        handle_cacheable_resource(req, res);
    } else if req.url[..] == "/events" {
        handle_sse_stream(req, res);
    } else if req.url[..] == "/proxy-target" {
        handle_proxy_backend(req, res);
    }
    var tx_buf: u8[..4096] = [];
    wing::serialize_http1_response(res, "goose-wing-e2e", tx_buf);
    let sent = wing::tcp_send(sfd, tx_buf[..]);
    wing::tcp_close(sfd);
    return sent == tx_buf.len;
}

// ---- 1. Live SOCKS5 & HTTP CONNECT Proxy Tunnels ---------------------------

fn test_live_proxy_tunnels() {
    let srv_lfd = wing::tcp_listen("127.0.0.1", 0);
    let prx_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(srv_lfd > 0 && prx_lfd > 0);
    let srv_port = wing::tcp_getsockname_port(srv_lfd);
    let prx_port = wing::tcp_getsockname_port(prx_lfd);

    // 1A. Verify live SOCKS5h RFC 1928 + RFC 1929 Username/Password client<->server handshake
    let c_socks = wing::tcp_connect("127.0.0.1", prx_port, 200);
    let s_socks = wing::tcp_accept(prx_lfd, 200);
    assert(c_socks > 0 && s_socks > 0);

    // Pre-send server replies (method selection [0x05, 0x02], RFC 1929 auth [0x01, 0x00], CONNECT reply)
    // so `socks5_client_handshake` executes end-to-end over the live socket!
    let srv_socks_script: u8[14] = [
        0x05, 0x02,
        0x01, 0x00,
        0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00,
    ];
    assert(wing::tcp_send(s_socks, srv_socks_script[..]) == 14);
    let s5_err = wing::socks5_client_handshake(
        c_socks, wing::ProxyScheme.Socks5h, "origin.internal", srv_port, "alice", "s3cret", 200,
    );
    assert(s5_err == wing::Socks5Error.None);

    var s5_rx: u8[..128] = [];
    let n_s5 = wing::tcp_recv(s_socks, s5_rx, 128, 200);
    assert(n_s5 > 10 && s5_rx[0] == 0x05 && s5_rx[4] == 0x01); // Greeting 0x05 + RFC 1929 0x01
    assert(find_subslice(s5_rx[..n_s5], "origin.internal") >= 0); // ATYP=0x03 domain for socks5h://
    wing::tcp_close(c_socks);
    wing::tcp_close(s_socks);

    // 1B. Verify live HTTP CONNECT tunnel client<->server handshake with Proxy-Authorization
    let c_hc = wing::tcp_connect("127.0.0.1", prx_port, 200);
    let s_hc = wing::tcp_accept(prx_lfd, 200);
    assert(c_hc > 0 && s_hc > 0);
    let connect_200 = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: wing-proxy\r\n\r\n";
    assert(wing::tcp_send(s_hc, connect_200) == connect_200.len);
    let hc_err = wing::http_connect_client_handshake(
        c_hc, "origin.internal", srv_port, "Basic YWxpY2U6czNjcmV0", "goose-wing/1.0", 200,
    );
    assert(hc_err == wing::ConnectTunnelError.None);
    var hc_rx: u8[..512] = [];
    let n_hc = wing::tcp_recv(s_hc, hc_rx, 512, 200);
    assert(n_hc > 0 && find_subslice(hc_rx[..n_hc], "CONNECT origin.internal:") >= 0);
    assert(find_subslice(hc_rx[..n_hc], "Proxy-Authorization: Basic YWxpY2U6czNjcmV0") >= 0);
    wing::tcp_close(c_hc);
    wing::tcp_close(s_hc);

    // 1C. Now tunnel an HTTP/1.1 request through `wing::Client` with `proxy_url` -> origin server
    let srv_conn_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let srv_conn_s = wing::tcp_accept(srv_lfd, 200);
    assert(srv_conn_c > 0 && srv_conn_s > 0);

    g_e2e_client = wing::Client { .. };
    g_e2e_client.virtual_clock_us = 1;
    let _ = g_e2e_client.proxy_url.try_set("http://alice:s3cret@127.0.0.1:18888");
    let proxy_chain = wing::resolve_hop_proxy_chain(g_e2e_client);
    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        proxy_chain,
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp_direct_tun: wing::Transport = wing::Transport.Tcp { fd: srv_conn_c };
    let cid_tun = wing::register_connection(
        g_e2e_client.pool, pkey, wing::NegotiatedProtocol.Http11, tp_direct_tun, "127.0.0.1", 1, 1000,
    );
    wing::release_connection(g_e2e_client.pool, cid_tun, 1000);

    var url_tun: u8[..128] = [];
    url_tun.append("http://127.0.0.1:");
    core::format_u64_dec(srv_port, url_tun);
    url_tun.append("/tunnel-check");

    var req_tun = wing::new_get(url_tun[..]);
    // Attach a Proxy-Authorization header that MUST be stripped by `execute_live_network_hop` when `!proxy_chain.is_direct`
    wing::set_header(req_tun, "Proxy-Authorization", "Basic YWxpY2U6czNjcmV0");
    wing::set_header(req_tun, "Proxy-Connection", "keep-alive");

    let canned_origin_resp = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nX-Origin-Reached: yes\r\n\r\nTUNNEL_ORIGIN_OK";
    assert(wing::tcp_send(srv_conn_s, canned_origin_resp) == canned_origin_resp.len);

    let resp_tun, err_tun = wing::execute_request(g_e2e_client, req_tun);
    assert(wing::ok(err_tun) && resp_tun.status_code == 200);
    assert(resp_tun.body[..] == "TUNNEL_ORIGIN_OK");

    // Read the exact wire bytes received by the origin server on `srv_conn_s` and feed them into our live server!
    var origin_rx: u8[..2048] = [];
    let n_orig = wing::tcp_recv(srv_conn_s, origin_rx, 2048, 200);
    assert(n_orig > 0);
    assert(find_subslice(origin_rx[..n_orig], "Proxy-Authorization") < 0);
    assert(find_subslice(origin_rx[..n_orig], "Proxy-Connection") < 0);

    let v_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, origin_rx[..n_orig]) == n_orig);
    assert(accept_and_serve_one_e2e(srv_lfd));
    var srv_out: u8[..1024] = [];
    let n_so = wing::tcp_recv(v_c, srv_out, 1024, 200);
    assert(n_so > 0 && find_subslice(srv_out[..n_so], "TUNNEL_ORIGIN_OK:/tunnel-check") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(srv_conn_c);
    wing::tcp_close(srv_conn_s);
    wing::tcp_close(srv_lfd);
    wing::tcp_close(prx_lfd);
    print("E2E_LIVE_PROXY_TUNNELS: OK");
}

// ---- 2. Live 401 Digest SHA-256 Challenge-Response + Cookie Jar ------------

fn test_live_digest_auth_and_cookies() {
    let srv_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(srv_lfd > 0);
    let srv_port = wing::tcp_getsockname_port(srv_lfd);

    let c_fd = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let s_fd = wing::tcp_accept(srv_lfd, 200);
    assert(c_fd > 0 && s_fd > 0);

    g_e2e_client = wing::Client { .. };
    g_e2e_client.virtual_clock_us = 1700000000000000;
    let _ = g_e2e_client.creds.username.try_set("admin");
    let _ = g_e2e_client.creds.password.try_set("hunter2");
    g_e2e_client.creds.has_credentials = true;

    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp: wing::Transport = wing::Transport.Tcp { fd: c_fd };
    let cid_auth = wing::register_connection(
        g_e2e_client.pool, pkey, wing::NegotiatedProtocol.Http11, tp, "127.0.0.1", 1, 1700000000000000000,
    );
    wing::release_connection(g_e2e_client.pool, cid_auth, 1700000000000000000);

    // Queue the 2 pipelined HTTP/1.1 Keep-Alive responses on `s_fd` (401 challenge + 200 OK),
    // then verify the 2 requests emitted by `wing::Client` against `handle_digest_protected`!
    var resp_401_and_200: u8[..1024] = [];
    resp_401_and_200.append("HTTP/1.1 401 Unauthorized\r\n");
    resp_401_and_200.append("WWW-Authenticate: Digest realm=\"wing-api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=SHA-256, opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n");
    resp_401_and_200.append("Set-Cookie: auth_step=challenged; Path=/\r\n");
    resp_401_and_200.append("Content-Length: 12\r\n\r\nUNAUTHORIZED");
    resp_401_and_200.append("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nDIGEST_AUTH_OK");
    assert(wing::tcp_send(s_fd, resp_401_and_200[..]) == resp_401_and_200.len);

    var url_auth: u8[..128] = [];
    url_auth.append("http://127.0.0.1:");
    core::format_u64_dec(srv_port, url_auth);
    url_auth.append("/digest-protected");

    let req_auth = wing::new_get(url_auth[..]);
    let resp_auth, err_auth = wing::execute_request(g_e2e_client, req_auth);
    assert(wing::ok(err_auth) && resp_auth.status_code == 200);
    assert(resp_auth.body[..] == "DIGEST_AUTH_OK");
    assert(wing::get(g_e2e_client.jar, "auth_step") == "challenged");

    // Read both wire requests emitted by `wing::Client` over `s_fd` and replay the 2nd (authenticated) request
    // against `accept_and_serve_one_e2e` (`handle_digest_protected`)!
    var wire_both: u8[..4096] = [];
    let n_both = wing::tcp_recv(s_fd, wire_both, 4096, 200);
    assert(n_both > 0);
    assert(find_subslice(wire_both[..n_both], "Authorization: Digest ") >= 0);
    let second_get_pos = find_subslice(wire_both[16..n_both], "GET /digest-protected");
    assert(second_get_pos >= 0);
    let req2_slice = wire_both[16 + second_get_pos..n_both];

    let v_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, req2_slice) == req2_slice.len);
    assert(accept_and_serve_one_e2e(srv_lfd));
    var srv_out: u8[..1024] = [];
    let n_so = wing::tcp_recv(v_c, srv_out, 1024, 200);
    assert(n_so > 0 && find_subslice(srv_out[..n_so], "200 OK") >= 0);
    assert(find_subslice(srv_out[..n_so], "DIGEST_AUTH_OK") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(c_fd);
    wing::tcp_close(s_fd);
    wing::tcp_close(srv_lfd);
    print("E2E_LIVE_DIGEST_AUTH_AND_COOKIES: OK");
}

// ---- 3. Live RFC 9111 HTTP Cache Revalidation (200 -> Hit -> 304) ----------

fn test_live_http_cache_revalidation() {
    let srv_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(srv_lfd > 0);
    let srv_port = wing::tcp_getsockname_port(srv_lfd);

    let c_fd = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let s_fd = wing::tcp_accept(srv_lfd, 200);
    assert(c_fd > 0 && s_fd > 0);

    g_e2e_client = wing::Client { .. };
    g_e2e_client.virtual_clock_us = 1000000000; // t = 1000s
    g_e2e_client.enable_cache = true;

    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp: wing::Transport = wing::Transport.Tcp { fd: c_fd };
    let cid_cache = wing::register_connection(
        g_e2e_client.pool, pkey, wing::NegotiatedProtocol.Http11, tp, "127.0.0.1", 1, 1000000000000,
    );
    wing::release_connection(g_e2e_client.pool, cid_cache, 1000000000000);

    // Queue initial 200 OK (max-age=10, ETag="v42") and subsequent 304 Not Modified on the Keep-Alive socket
    var wire_200_and_304: u8[..1024] = [];
    wire_200_and_304.append("HTTP/1.1 200 OK\r\nETag: \"v42\"\r\nCache-Control: max-age=10\r\nX-Cache-Freshened: false\r\nContent-Length: 23\r\n\r\nCACHED_LIVE_PAYLOAD_V42");
    wire_200_and_304.append("HTTP/1.1 304 Not Modified\r\nETag: \"v42\"\r\nCache-Control: max-age=60\r\nX-Cache-Freshened: true\r\n\r\n");
    assert(wing::tcp_send(s_fd, wire_200_and_304[..]) == wire_200_and_304.len);

    var url_cache: u8[..128] = [];
    url_cache.append("http://127.0.0.1:");
    core::format_u64_dec(srv_port, url_cache);
    url_cache.append("/cache-item");

    // Step 1 (t = 1000s): Miss -> fetches 200 OK from socket and stores in cache
    let req1 = wing::new_get(url_cache[..]);
    let resp1, err1 = wing::execute_request(g_e2e_client, req1);
    assert(wing::ok(err1) && resp1.status_code == 200);
    assert(resp1.body[..] == "CACHED_LIVE_PAYLOAD_V42");
    assert(resp1.header("x-cache-freshened") == "false");

    // Drain 1st request from `s_fd`
    var req1_wire: u8[..1024] = [];
    let n_r1 = wing::tcp_recv(s_fd, req1_wire, 1024, 200);
    assert(n_r1 > 0 && find_subslice(req1_wire[..n_r1], "If-None-Match") < 0);

    // Step 2 (t = 1005s, within max-age=10): Fresh hit -> served from cache WITHOUT touching socket!
    g_e2e_client.virtual_clock_us = 1005000000;
    let resp2, err2 = wing::execute_request(g_e2e_client, req1);
    assert(wing::ok(err2) && resp2.status_code == 200);
    assert(resp2.body[..] == "CACHED_LIVE_PAYLOAD_V42");

    // Step 3 (t = 1025s, past max-age=10): Stale -> sends conditional `If-None-Match: "v42"` over live socket,
    // receives `304 Not Modified`, and synthesizes freshened 200 OK with cached body + new headers!
    g_e2e_client.virtual_clock_us = 1025000000;
    let resp3, err3 = wing::execute_request(g_e2e_client, req1);
    assert(wing::ok(err3) && resp3.status_code == 200);
    assert(resp3.body[..] == "CACHED_LIVE_PAYLOAD_V42");
    assert(resp3.header("x-cache-freshened") == "true");

    // Verify the conditional request sent over `s_fd` against `accept_and_serve_one_e2e` (`handle_cacheable_resource`)!
    var req3_wire: u8[..1024] = [];
    let n_r3 = wing::tcp_recv(s_fd, req3_wire, 1024, 200);
    assert(n_r3 > 0 && find_subslice(req3_wire[..n_r3], "If-None-Match: \"v42\"") >= 0);

    let v_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, req3_wire[..n_r3]) == n_r3);
    assert(accept_and_serve_one_e2e(srv_lfd));
    assert(g_reval_hits == 1);
    var srv_304: u8[..1024] = [];
    let n_s304 = wing::tcp_recv(v_c, srv_304, 1024, 200);
    assert(n_s304 > 0 && find_subslice(srv_304[..n_s304], "304 Not Modified") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(c_fd);
    wing::tcp_close(s_fd);
    wing::tcp_close(srv_lfd);
    print("E2E_LIVE_HTTP_CACHE_REVALIDATION: OK");
}

// ---- 4. Live Client<->Server WebSocket (H1 & H2) + W3C SSE -----------------

fn test_live_websocket_and_sse() {
    let lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd > 0);
    let port = wing::tcp_getsockname_port(lfd);

    // 4A. Live RFC 6455 HTTP/1.1 WebSocket Handshake + Masked/Unmasked Frames + Ping/Pong + Close
    let ws_c = wing::tcp_connect("127.0.0.1", port, 200);
    let ws_s = wing::tcp_accept(lfd, 200);
    assert(ws_c > 0 && ws_s > 0);

    var cli_ws = wing::new_websocket_session(true);
    cli_ws.subprotocol.append("chat");
    let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var hs_req_wire: u8[..512] = [];
    wing::build_handshake_request(cli_ws, "127.0.0.1", "/ws-live", client_key, hs_req_wire);
    assert(wing::tcp_send(ws_c, hs_req_wire[..]) == hs_req_wire.len);

    var srv_rx_hs: u8[..512] = [];
    let n_hs = wing::tcp_recv(ws_s, srv_rx_hs, 512, 200);
    assert(n_hs == hs_req_wire.len);
    var parsed_ws_req = wing::Request { .. };
    let ok_p_ws, _ = wing::parse_http1_wire_request(srv_rx_hs[..n_hs], parsed_ws_req);
    assert(ok_p_ws);
    var ws_srv_res = wing::Response { .. };
    var srv_ws, ok_upg = wing::ws_upgrade_request(parsed_ws_req, ws_srv_res, "chat");
    assert(ok_upg && ws_srv_res.status_code == 101 && srv_ws.subprotocol[..] == "chat");

    var hs_resp_wire: u8[..512] = [];
    wing::serialize_http1_response(ws_srv_res, "goose-wing-e2e", hs_resp_wire);
    assert(wing::tcp_send(ws_s, hs_resp_wire[..]) == hs_resp_wire.len);

    var cli_rx_hs: u8[..512] = [];
    let n_chs = wing::tcp_recv(ws_c, cli_rx_hs, 512, 200);
    assert(n_chs == hs_resp_wire.len);
    var parsed_ws_res = wing::Response { .. };
    assert(wing::parse_response_headers(cli_rx_hs[..n_chs - 4], parsed_ws_res));
    var expected_accept: u8[..64] = [];
    wing::compute_websocket_accept(client_key, expected_accept);
    assert(parsed_ws_res.header("sec-websocket-accept") == expected_accept[..]);

    // Client sends masked Text frame over live socket
    var cli_frame_wire: u8[..256] = [];
    wing::send_text(cli_ws, "HELLO_WS_LIVE", cli_frame_wire);
    assert(wing::tcp_send(ws_c, cli_frame_wire[..]) == cli_frame_wire.len);

    var srv_ws_rx: u8[..256] = [];
    let n_sws = wing::tcp_recv(ws_s, srv_ws_rx, 256, 200);
    assert(n_sws == cli_frame_wire.len);

    var srv_msg = wing::WsMessage { .. };
    var srv_reply: u8[..256] = [];
    assert(wing::receive(srv_ws, srv_ws_rx[..n_sws], srv_msg, srv_reply));
    assert(srv_msg.is_valid && srv_msg.opcode == rfc::WS_OPCODE_TEXT && srv_msg.data[..] == "HELLO_WS_LIVE");

    wing::send_text(srv_ws, "ACK:HELLO_WS_LIVE", srv_reply);
    assert(wing::tcp_send(ws_s, srv_reply[..]) == srv_reply.len);

    var cli_ws_rx: u8[..256] = [];
    let n_cws = wing::tcp_recv(ws_c, cli_ws_rx, 256, 200);
    assert(n_cws == srv_reply.len);
    var cli_msg = wing::WsMessage { .. };
    var cli_reply: u8[..256] = [];
    assert(wing::receive(cli_ws, cli_ws_rx[..n_cws], cli_msg, cli_reply));
    assert(cli_msg.is_valid && cli_msg.opcode == rfc::WS_OPCODE_TEXT && cli_msg.data[..] == "ACK:HELLO_WS_LIVE");

    wing::tcp_close(ws_c);
    wing::tcp_close(ws_s);

    // 4B. Live W3C Server-Sent Events (`SseSubscription` <-> live server with `Last-Event-ID` reconnect)
    var sub = wing::new_sse_subscription();
    var host_hdr: u8[..64] = [];
    host_hdr.append("127.0.0.1:");
    core::format_u64_dec(port, host_hdr);

    var sse_wire1: u8[..512] = [];
    wing::sse_build_request_headers(sub, host_hdr[..], "/events", sse_wire1);

    let sse_c1 = wing::tcp_connect("127.0.0.1", port, 200);
    assert(sse_c1 > 0);
    assert(wing::tcp_send(sse_c1, sse_wire1[..]) == sse_wire1.len);
    assert(accept_and_serve_one_e2e(lfd));

    var sse_rx1: u8[..1024] = [];
    let n_sse1 = wing::tcp_recv(sse_c1, sse_rx1, 1024, 200);
    wing::tcp_close(sse_c1);
    assert(n_sse1 > 0);
    let body_sep1 = find_subslice(sse_rx1[..n_sse1], "\r\n\r\n");
    assert(body_sep1 > 0);

    var events1: wing::SseEvent[..8] = [];
    wing::consume(sub, sse_rx1[body_sep1 + 4..n_sse1], events1);
    assert(events1.len == 2);
    assert(events1[0].event[..] == "tick" && events1[0].data[..] == "first-line\nsecond-line" && events1[0].id[..] == "ev-1");
    assert(events1[0].retry_ms == 1500);
    assert(events1[1].event[..] == "message" && events1[1].data[..] == "final-item" && events1[1].id[..] == "ev-2");
    assert(sub.parser.last_event_id[..] == "ev-2");

    // Reconnect with `Last-Event-ID: ev-2`
    var sse_wire2: u8[..512] = [];
    wing::sse_build_request_headers(sub, host_hdr[..], "/events", sse_wire2);
    assert(find_subslice(sse_wire2[..], "Last-Event-ID: ev-2") >= 0);

    let sse_c2 = wing::tcp_connect("127.0.0.1", port, 200);
    assert(sse_c2 > 0);
    assert(wing::tcp_send(sse_c2, sse_wire2[..]) == sse_wire2.len);
    assert(accept_and_serve_one_e2e(lfd));

    var sse_rx2: u8[..1024] = [];
    let n_sse2 = wing::tcp_recv(sse_c2, sse_rx2, 1024, 200);
    wing::tcp_close(sse_c2);
    assert(n_sse2 > 0);
    let body_sep2 = find_subslice(sse_rx2[..n_sse2], "\r\n\r\n");
    assert(body_sep2 > 0);
    var events2: wing::SseEvent[..8] = [];
    wing::consume(sub, sse_rx2[body_sep2 + 4..n_sse2], events2);
    assert(events2.len == 1 && events2[0].event[..] == "resumed" && events2[0].data[..] == "after-ev-2" && events2[0].id[..] == "ev-3");

    // 4C. Live HTTP/2 Extended CONNECT (RFC 8441 `:protocol = websocket`) over TCP socket
    let h2_c = wing::tcp_connect("127.0.0.1", port, 200);
    let h2_s = wing::tcp_accept(lfd, 200);
    assert(h2_c > 0 && h2_s > 0);

    var h2_ws_req = wing::Request { .. };
    wing::format_h2_websocket_request(h2_ws_req, "/ws-h2", "127.0.0.1", "https", "chat");
    var h2_ctx = wing::RequestExecutionContext { .. };
    h2_ctx.current_method.append("CONNECT");
    wing::copy_headers(h2_ws_req.headers, h2_ctx.headers);
    let h2_url = core::new_url("https://127.0.0.1/ws-h2");
    var dt_cli = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var h2_wire: u8[..2048] = [];
    assert(wing::encode_h2_client_request("CONNECT", h2_url, true, h2_ctx, dt_cli, 1, false, h2_wire));
    assert(wing::tcp_send(h2_c, h2_wire[..]) == h2_wire.len);

    var h2_srv_rx: u8[..2048] = [];
    let n_h2s = wing::tcp_recv(h2_s, h2_srv_rx, 2048, 200);
    assert(n_h2s == h2_wire.len);
    var fhdr, _, ok_fh = wire::parse_frame_header(h2_srv_rx[..9]);
    assert(ok_fh && fhdr.frame_type == rfc::H2_FRAME_HEADERS);
    var dt_srv = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var dec_pseudo = internal::H2PseudoHeaders { .. };
    var dec_map = wing::HeaderMap { .. };
    let dec_err = wire::decode_hpack_to_map(dt_srv, h2_srv_rx[9..9 + (fhdr.length as i64)], dec_pseudo, dec_map);
    assert(dec_err == rfc::H2_ERR_NO_ERROR);
    var st = internal::H2ServerStream { stream_id: 1, active: true, .. };
    assert(internal::apply_decoded_pseudo_to_stream(st, dec_pseudo));
    wing::append_all_headers(dec_map, st.headers);
    var h2_parsed_req = wing::new_request(st.method[..], st.path[..]);
    internal::copy_stream_headers_and_trailers(st, h2_parsed_req);
    assert(wing::validate_h2_websocket_request(h2_parsed_req));
    wing::tcp_close(h2_c);
    wing::tcp_close(h2_s);

    wing::tcp_close(lfd);
    print("E2E_LIVE_WEBSOCKET_AND_SSE: OK");
}

// ---- 5. Live ReverseProxy + LoadBalancer Failover --------------------------

fn test_live_reverse_proxy_failover() {
    // Allocate a dead port by opening and immediately closing a listener
    let dead_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(dead_lfd > 0);
    let dead_port = wing::tcp_getsockname_port(dead_lfd);
    wing::tcp_close(dead_lfd);

    // Live backend listener
    let live_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(live_lfd > 0);
    let live_port = wing::tcp_getsockname_port(live_lfd);

    g_e2e_proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    g_e2e_proxy.cluster.max_fails = 1;
    assert(wing::add_upstream_target(g_e2e_proxy.cluster, "127.0.0.1", dead_port, 1));
    assert(wing::add_upstream_target(g_e2e_proxy.cluster, "127.0.0.1", live_port, 1));
    g_e2e_proxy.cluster.targets[0].unhealthy_threshold = 1;

    g_e2e_pool = wing::StreamPool { .. };
    var in_hdrs = wing::HeaderMap { .. };
    let _ = wing::append_header(in_hdrs, "Host", "edge.example.com");
    let _ = wing::append_header(in_hdrs, "Connection", "keep-alive, x-secret-hop");
    let _ = wing::append_header(in_hdrs, "X-Secret-Hop", "must-be-stripped");

    // Attempt 1 hits Target 0 (dead port), fails fast, and marks Target 0 unhealthy
    var out_resp1 = wing::Response { .. };
    let ok1 = wing::execute_proxy_exchange(
        g_e2e_proxy, g_e2e_pool, "GET", "/proxy-target", in_hdrs, "198.51.100.77", "http", "", out_resp1, 150, 1000,
    );
    assert(!ok1);
    assert(!g_e2e_proxy.cluster.targets[0].is_healthy);

    // Pre-accept pooled backend connection for Target 1 so synchronous exchange completes
    // and we verify the exact upstream wire request on `accept_and_serve_one_e2e`!
    let b_cli = wing::tcp_connect("127.0.0.1", live_port, 200);
    let b_srv = wing::tcp_accept(live_lfd, 200);
    assert(b_cli > 0 && b_srv > 0);

    let b_pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", live_port,
        wing::new_direct_proxy_chain(),
        wing::NetworkAnonymizationKey { .. },
        wing::TlsAndDnsPolicy { .. },
    );
    let b_tp: wing::Transport = wing::Transport.Tcp { fd: b_cli };
    let cid_b = wing::register_connection(g_e2e_pool, b_pkey, wing::NegotiatedProtocol.Http11, b_tp, "127.0.0.1", 1, 1000);
    wing::release_connection(g_e2e_pool, cid_b, 1000);

    let backend_wire_resp = "HTTP/1.1 200 OK\r\nX-Backend-Handled: true\r\nContent-Length: 16\r\n\r\nUPSTREAM_LIVE_OK";
    assert(wing::tcp_send(b_srv, backend_wire_resp) == backend_wire_resp.len);

    // Attempt 2 automatically selects healthy Target 1 (`live_port`) and succeeds!
    var out_resp2 = wing::Response { .. };
    let ok2 = wing::execute_proxy_exchange(
        g_e2e_proxy, g_e2e_pool, "GET", "/proxy-target", in_hdrs, "198.51.100.77", "http", "", out_resp2, 200, 2000,
    );
    assert(ok2 && out_resp2.status_code == 200);
    assert(out_resp2.body[..] == "UPSTREAM_LIVE_OK");
    assert(out_resp2.header("x-backend-handled") == "true");

    // Read the exact upstream request produced by `execute_proxy_exchange` on `b_srv`
    // and feed it into `accept_and_serve_one_e2e` (`handle_proxy_backend`) to verify XFF, Via, and hop-by-hop stripping!
    var up_req_wire: u8[..2048] = [];
    let n_up = wing::tcp_recv(b_srv, up_req_wire, 2048, 200);
    assert(n_up > 0);

    let v_c = wing::tcp_connect("127.0.0.1", live_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, up_req_wire[..n_up]) == n_up);
    assert(accept_and_serve_one_e2e(live_lfd));
    var srv_out: u8[..1024] = [];
    let n_so = wing::tcp_recv(v_c, srv_out, 1024, 200);
    assert(n_so > 0 && find_subslice(srv_out[..n_so], "UPSTREAM_LIVE_OK") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(b_cli);
    wing::tcp_close(b_srv);
    wing::tcp_close(live_lfd);
    print("E2E_LIVE_REVERSE_PROXY_FAILOVER: OK");
}

fn run_02_verify_live_e2e_workflows() {
    test_live_proxy_tunnels();
    test_live_digest_auth_and_cookies();
    test_live_http_cache_revalidation();
    test_live_websocket_and_sse();
    test_live_reverse_proxy_failover();
}

// CHECK: E2E_LIVE_PROXY_TUNNELS: OK
// CHECK-NEXT: E2E_LIVE_DIGEST_AUTH_AND_COOKIES: OK
// CHECK-NEXT: E2E_LIVE_HTTP_CACHE_REVALIDATION: OK
// CHECK-NEXT: E2E_LIVE_WEBSOCKET_AND_SSE: OK
// CHECK-NEXT: E2E_LIVE_REVERSE_PROXY_FAILOVER: OK

// ============================================================================
// 3. verify_module_seams_regress (3/12)
// ============================================================================
// CHECK: === [3/12] verify_module_seams_regress ===

// tests/lit/verify_module_seams_regress.goose
// Regression test suite for cross-module integration seams (H2/H3 client/server bridges,
// pipeline stage ordering, TLS SNI routing, and TLS X.509 SAN connection coalescing).
//

var g_seam_server:  wing::HttpServer       = wing::new_http_server("goose-wing/1.0");
var g_seam_session: wing::Session          = wing::new_session();
var g_seam_pool:    wing::StreamPool       = wing::StreamPool { .. };
var g_cli_h3:       internal::H3Connection = internal::H3Connection { .. };
var g_srv_h3_1:     internal::H3Connection = internal::H3Connection { .. };
var g_srv_h3_2:     internal::H3Connection = internal::H3Connection { .. };

// 1. Bug 1 & Bug 2: Client HTTP/2 multi-frame / multi-read response drain + trailing HEADERS (gRPC)
fn test_client_h2_trailers_and_incremental_drain() {
    var enc_dt = internal::new_dynamic_table(4096);
    var dec_dt = internal::new_dynamic_table(4096);

    // Build initial response HEADERS (:status = 200, content-type = application/grpc) without END_STREAM
    var init_pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var init_hdrs = wing::HeaderMap { .. };
    wing::append_header(init_hdrs, "content-type", "application/grpc");

    var chunk1: u8[..1024] = [];
    assert(wire::encode_h2_headers_frame_from_map(enc_dt, 1, init_pseudo, init_hdrs, false, chunk1, 16384));

    // Build DATA frame (without END_STREAM) + Trailing HEADERS frame (grpc-status: 0, END_STREAM = true)
    var chunk2: u8[..1024] = [];
    assert(wire::encode_data_frame(1, "GRPC_PAYLOAD", false, chunk2));

    var trail_pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
    var trail_hdrs = wing::HeaderMap { .. };
    wing::append_header(trail_hdrs, "grpc-status", "0");
    wing::append_header(trail_hdrs, "grpc-message", "OK");
    assert(wire::encode_h2_headers_frame_from_map(enc_dt, 1, trail_pseudo, trail_hdrs, true, chunk2, 16384));

    // Feed chunk1 then chunk2 into rx_accum (simulating 2 socket reads in recv_h2_response_loop)
    var rx_accum: u8[..4096] = [];
    var resp = wing::Response { .. };
    var got_hdrs = false;
    var ctrl_out: u8[..256] = [];

    rx_accum.append(chunk1[..]);
    let ok1, done1 = wing::drain_h2_response_frames(rx_accum, 1, false, dec_dt, resp, got_hdrs, ctrl_out);
    assert(ok1 && !done1 && got_hdrs);
    assert(rx_accum.len == 0); // Must drain consumed frame bytes so read 2 does not re-decode chunk1!

    rx_accum.append(chunk2[..]);
    let ok2, done2 = wing::drain_h2_response_frames(rx_accum, 1, false, dec_dt, resp, got_hdrs, ctrl_out);
    assert(ok2 && done2);
    assert(resp.status_code == 200);
    assert(wing::header(resp, "content-type") == "application/grpc");
    assert(resp.body[..] == "GRPC_PAYLOAD");
    assert(wing::trailer(resp, "grpc-status") == "0");
    assert(wing::trailer(resp, "grpc-message") == "OK");
    print("SEAM_H2_CLIENT_TRAILERS_DRAIN: OK");
}

// 2. Bug 3 & Bug 4: Client HTTP/3 request query string preservation + Server HTTP/3 trailers roundtrip
fn test_h3_query_and_trailers_seam() {
    assert(wing::add_static_route(g_seam_server.pipeline.router, "POST", "/grpc.Echo/Call", "application/grpc", "H3_GRPC_BODY", 77));

    // Client builds HTTP/3 request for URL with query string "?trace=99&mode=fast"
    let u = core::new_url("https://example.com/grpc.Echo/Call?trace=99&mode=fast");
    var ctx = wing::RequestExecutionContext { .. };
    ctx.current_method.append("POST");
    ctx.body.append("REQ_DATA");
    wing::append_header(ctx.headers, "te", "trailers");

    let h3_settings = wing::H3Settings { .. };
    g_cli_h3 = internal::new_h3_client_connection(h3_settings);
    let sid, ok_s = internal::open_request_stream(g_cli_h3);
    assert(ok_s && sid == 0);

    var req_wire: u8[..4096] = [];
    assert(wing::encode_h3_client_request(g_cli_h3, sid, ctx, u, req_wire));

    g_srv_h3_1 = internal::new_h3_server_connection(h3_settings);
    var tx_wire: u8[..4096] = [];
    assert(wing::handle_h3_server_datagram(g_seam_server, g_srv_h3_1, sid, "127.0.0.1", req_wire[..], 1000, tx_wire));

    // Verify server received the full :path including "?trace=99&mode=fast"
    assert(g_srv_h3_1.streams[0].req_path[..] == "/grpc.Echo/Call?trace=99&mode=fast");

    // Verify server HTTP/3 response encoder emits trailing HEADERS when trailers are present
    var srv_trailers = wing::HeaderMap { .. };
    wing::append_header(srv_trailers, "grpc-status", "0");
    var tx_with_trailers: u8[..4096] = [];
    g_srv_h3_2 = internal::new_h3_server_connection(h3_settings);
    assert(internal::handle_stream_data(g_srv_h3_2, sid, true, req_wire[..], true) == rfc::H3_ERR_NO_ERROR);
    var extra_hdrs = wing::HeaderMap { .. };
    wing::append_header(extra_hdrs, "content-type", "application/grpc");
    assert(internal::send_response_headers_body_and_trailers(
        g_srv_h3_2, sid, 200, extra_hdrs, "H3_GRPC_BODY", srv_trailers, tx_with_trailers,
    ));

    let h_err = internal::handle_stream_data(g_cli_h3, sid, true, tx_with_trailers[..], true);
    assert(h_err == rfc::H3_ERR_NO_ERROR);
    var cli_trailers = wing::HeaderMap { .. };
    assert(internal::copy_stream_trailers(g_cli_h3, sid, cli_trailers));
    assert(wing::get_header(cli_trailers, "grpc-status") == "0");
    print("SEAM_H3_QUERY_AND_TRAILERS: OK");
}

// 3. Bug 5: Client WirePipeline.egress_stages custom ordering
fn test_client_egress_pipeline_custom_order() {
    // Configure egress_stages with only REDIRECT (omitting COOKIE_STORE)
    g_seam_session.wire_pipeline.egress_stages.clear();
    g_seam_session.wire_pipeline.egress_stages.push(wire::STAGE_ID_CLI_OUT_REDIRECT);

    wing::mock_route(g_seam_session, "GET", "https://example.com/start", 302, "");
    wing::add_mock_header(g_seam_session, "Location", "https://example.com/final");
    wing::add_mock_set_cookie(g_seam_session, "skipped_cookie=1; Path=/");
    wing::mock_route(g_seam_session, "GET", "https://example.com/final", 200, "done");

    var req = wing::new_get("https://example.com/start");
    let resp, err = wing::execute_request(g_seam_session, req);
    assert(wing::ok(err) && resp.status_code == 200);
    // Because STAGE_ID_CLI_OUT_COOKIE_STORE was omitted from egress_stages, cookie must not be stored
    assert(wing::get(g_seam_session.jar, "skipped_cookie") == "");
    print("SEAM_CLIENT_EGRESS_STAGES_ORDER: OK");
}

// 4. Bug 6: Server TLS ClientHello SNI extraction & SniRegistry wiring
fn test_server_tls_sni_extraction() {
    let client_random: u8[32] = [0x11; 32];
    let client_pub:    u8[32] = [0x22; 32];
    var ch_payload: u8[..2048] = [];
    wing::build_tls13_client_hello_payload(
        client_random, client_pub, "Api.Example.COM", "h2,http/1.1", ch_payload,
    );
    var ch_msg: u8[..2048] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_msg, ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    var sid:         u8[..32]  = [];
    var out_pub:     u8[32]    = [0; 32];
    var out_alpn:    u8[..32]  = [];
    var out_sni:     u8[..255] = [];
    var psk_resumed: bool      = false;
    var psk_secret:  u8[32]    = [0; 32];

    assert(wing::parse_client_hello_for_server_sni(
        ch_msg[..], "h2,http/1.1", sid, out_pub, out_alpn, out_sni, psk_resumed, psk_secret,
    ));
    assert(out_alpn[..] == "h2");
    assert(out_sni[..] == "api.example.com");
    print("SEAM_TLS_SERVER_SNI: OK");
}

// 5. Bug 7: Client TLS X.509 SAN extraction -> PooledConnection HTTP/2 IP coalescing
fn test_tls_san_to_pool_coalescing() {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(seed, "example.com", "*.example.com", "93.184.216.34", cert_der));

    let slot_idx = wing::alloc_tls_cipher_slot();
    assert(slot_idx != 0xFFFF);
    assert(wing::tls_populate_slot_san_hosts_from_der(slot_idx, cert_der[..]));

    let direct_proxy = wing::new_direct_proxy_chain();
    let nak = wing::NetworkAnonymizationKey { .. };
    let pol = wing::TlsAndDnsPolicy { .. };
    var key_a = wing::new_pool_key(wing::PoolScheme.Https, "a.example.com", 443, direct_proxy, nak, pol);
    var key_b = wing::new_pool_key(wing::PoolScheme.Https, "b.example.com", 443, direct_proxy, nak, pol);
    let tp = wing::Transport.Tls { fd: 99, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot_idx };

    let cid = wing::register_connection(g_seam_pool, key_a, wing::NegotiatedProtocol.Http2, tp, "93.184.216.34", 100, 1000);
    assert(cid > 0);
    let coalesced_id, ok_coal = wing::acquire_pooled_connection(g_seam_pool, key_b, "93.184.216.34", 1001);
    assert(ok_coal && coalesced_id == cid);

    wing::free_tls_cipher_slot(slot_idx);
    print("SEAM_TLS_SAN_POOL_COALESCING: OK");
}

struct TestCustomEchoStage {
    active: bool = true,
}

fn wing::on_server_stage(
    _stage: TestCustomEchoStage&,
    phase:  wire::ServerHookPhase,
    _cfg:   wing::ServerPipelineConfig&,
    req:    const wing::Request&,
    _ctx:   wing::ServerStageCtx&,
    res:    wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PostAuth && req.url[..] == "/echo" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "text/plain");
        res.body.clear();
        res.body.append("ECHO:");
        res.body.append(req.body[..]);
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    return wire::StageVerdict.Continue;
}

// 6. Bug 8: Server custom <UserStage> hook phase and ShortCircuit verdict integration
fn test_server_custom_stage_hook_seam() {
    wing::add_post_route(g_seam_server, "/echo", 202);
    var req = wing::new_request("POST", "/echo");
    wing::append_header(req.headers, "Host", "example.com");
    wing::append_header(req.headers, "Sec-Fetch-Site", "same-origin");
    req.body.append("payload42");

    var res = wing::Response { .. };
    var echo_stage = TestCustomEchoStage { .. };
    let outcome = wing::dispatch_server_request_with_stage(g_seam_server, "127.0.0.1", req, 2000, res, echo_stage);
    assert(outcome == wing::PipelineOutcome.Handled);
    assert(res.status_code == 200);
    assert(res.body[..] == "ECHO:payload42");
    print("SEAM_SERVER_CUSTOM_STAGE_HOOK: OK");
}

var g_h2_srv_sess = internal::new_h2_server_session("goose-wing/1.0", 1000);

fn test_h2_server_flow_window_and_closed_stream_seams() {
    wing::add_static_get_route(g_seam_server, "/ping", "text/plain", "PONG", 77);
    var client_dt = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

    var wire1: u8[..256] = [];
    wire1.append(rfc::H2_CLIENT_PREFACE[..]);
    // SETTINGS: INITIAL_WINDOW_SIZE (0x04) = 0
    let set_hdr = internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    internal::encode_frame_header_to(set_hdr, wire1);
    core::append_u16_be(wire1, rfc::H2_SETTING_INITIAL_WINDOW_SIZE);
    core::append_u32_be(wire1, 0);

    var req_hblock: u8[..128] = [];
    internal::encode_hpack_field(client_dt, req_hblock, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, req_hblock, ":scheme", "http", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, req_hblock, ":path", "/ping", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, req_hblock, ":authority", "localhost", internal::HpackIndexing.Incremental, false);
    let h_hdr = internal::FrameHeader {
        length:     req_hblock.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  5,
    };
    internal::encode_frame_header_to(h_hdr, wire1);
    wire1.append(req_hblock[..]);

    var out1: u8[..1024] = [];
    let _, ok1 = internal::handle_h2_server_ingress(g_h2_srv_sess, g_seam_server.pipeline, g_seam_server.timer, "127.0.0.1", wire1[..], 1000, out1);
    assert(ok1);
    assert(g_h2_srv_sess.conn.active_stream_count == 1);

    // Grant 4 bytes via WINDOW_UPDATE on stream 5
    var wire2: u8[..64] = [];
    internal::emit_window_update(5, 4, wire2);
    var out2: u8[..1024] = [];
    let _, ok2 = internal::handle_h2_server_ingress(g_h2_srv_sess, g_seam_server.pipeline, g_seam_server.timer, "127.0.0.1", wire2[..], 1010, out2);
    assert(ok2);
    assert(out2.len == 13 && out2[3] == rfc::H2_FRAME_DATA && (out2[4] & rfc::H2_FLAG_END_STREAM) != 0);
    assert(g_h2_srv_sess.conn.active_stream_count == 0);

    // Sending smaller stream ID (3 < 5) that was implicitly closed by opening stream 5 (RFC 9113 §5.1.1) returns STREAM_CLOSED
    let small_hdr = internal::FrameHeader {
        length:     req_hblock.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  3,
    };
    let err_small = internal::on_ingress_frame_header(g_h2_srv_sess.conn, small_hdr, 1020);
    assert(err_small == rfc::H2_ERR_STREAM_CLOSED);
    print("SEAM_H2_FLOW_AND_CLOSED_STREAMS: OK");
}

// Seam 8: HTTP/2 client `recv_h2_response_loop` must continue reading across >16 sliced chunks
// until END_STREAM (`done == true`) rather than truncating after 16 reads or returning after HEADERS-only.
fn test_h2_client_sliced_stream_recv_seam() {
    let cli_fd = wing::udp_bind("127.0.0.1", 0);
    let srv_fd = wing::udp_bind("127.0.0.1", 0);
    assert(cli_fd > 0 && srv_fd > 0);
    let cli_port = wing::tcp_getsockname_port(cli_fd);

    var srv_enc = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var hblock: u8[..128] = [];
    internal::encode_hpack_field(srv_enc, hblock, ":status", "200", internal::HpackIndexing.Incremental, false);

    var wire: u8[..256] = [];
    let h_hdr = internal::FrameHeader {
        length:     hblock.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    internal::encode_frame_header_to(h_hdr, wire);
    wire.append(hblock[..]);

    let body_msg = "SLICED_H2_BODY_PAYLOAD_24_CHUNKS_OK";
    let d_hdr = internal::FrameHeader {
        length:     body_msg.len as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    internal::encode_frame_header_to(d_hdr, wire);
    wire.append(body_msg);

    // Send 1 byte per datagram (> 50 datagrams total, exceeding the old 16-step cap)
    for i in wire.len {
        let _ = wing::native_udp_sendto(srv_fd, wire[i..i + 1], "127.0.0.1", cli_port);
    }

    var tp: wing::Transport = wing::Transport.Udp { fd: cli_fd, peer_ip4: 0x7F000001, peer_port: 9999 };
    var cli_dec = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var resp = wing::Response { .. };
    let ok_h2 = wing::recv_h2_response_loop(tp, 1, false, cli_dec, 200, resp);
    wing::tcp_close(cli_fd);
    wing::tcp_close(srv_fd);

    assert(ok_h2);
    assert(resp.status_code == 200);
    assert(resp.body[..] == body_msg);
    print("SEAM_H2_CLIENT_SLICED_STREAM: OK");
}

// Seam 10 & 11: HTTP/1.1 client `parse_response_headers` must preserve the final header line
// when `conn.rx_buf[..hdr_end_idx]` is sliced at `\r\n\r\n`, and `dispatch_pooled_h1_hop`
// must clear `Request.method` default `"GET"` before setting `curr_method` (not emit `"GETHEAD"`).
fn test_h1_client_last_response_header_preserved_seam() {
    let raw_rx = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nConnection: close\r\n\r\nOK";
    let hdr_end_idx = core::fast_find_crlfcrlf(raw_rx);
    assert(hdr_end_idx > 0);
    var resp = wing::Response { .. };
    assert(wing::parse_response_headers(raw_rx[..hdr_end_idx], resp));
    assert(resp.status_code == 200);
    assert(resp.header("Content-Type") == "text/plain");
    assert(resp.header("Set-Cookie") == "a=1");
    assert(resp.header("Connection") == "close");

    let lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd > 0);
    let srv_port = wing::tcp_getsockname_port(lfd);
    let cli_fd = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let srv_fd = wing::tcp_accept(lfd, 200);
    assert(cli_fd > 0 && srv_fd > 0);
    let head_resp = "HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n";
    let _ = wing::tcp_send(srv_fd, head_resp);

    g_seam_session.timeout_ms = 200;
    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp: wing::Transport = wing::Transport.Tcp { fd: cli_fd };
    let cid = wing::register_connection(g_seam_session.pool, pkey, wing::NegotiatedProtocol.Http11, tp, "127.0.0.1", 1, 1000);
    var ctx = wing::RequestExecutionContext { .. };
    let u = core::new_url("http://127.0.0.1/head-check");
    var hop_resp = wing::Response { .. };
    let ok_hop = wing::dispatch_pooled_h1_hop(g_seam_session, cid, "HEAD", ctx, u, false, "http://127.0.0.1", "/head-check", 1, 1000, hop_resp);
    var wire_req: u8[..512] = [];
    let n_req = wing::tcp_recv(srv_fd, wire_req, 512, 100);
    wing::tcp_close(srv_fd);
    wing::tcp_close(lfd);

    assert(ok_hop);
    assert(n_req >= 16);
    assert(core::starts_with(wire_req[..n_req], "HEAD /head-check HTTP/1.1\r\n"));
    print("SEAM_H1_LAST_RESPONSE_HEADER: OK");
}

fn seam_grpc_echo_handler(
    route_tag: u16,
    ctx:       wing::GrpcServerContext&,
    payload:   const u8[:],
    out_body:  u8[>..]&,
) -> wing::GrpcStatus {
    let _ = route_tag;
    let _ = ctx;
    out_body.append(payload);
    return wing::grpc_ok();
}

// Seam 12, 13 & 14:
// - `build_tls13_client_hello_payload` with IP literal ("127.0.0.1") must NOT emit illegal
//   RFC 6066 SNI HostName extension that `parse_client_hello_for_server_sni` rejects.
// - `emit_grpc_h2_response_frames` must split payloads > 16384 bytes across multiple DATA frames.
// - `handle_grpc_h2_wire_frame` must wait for `H2_FLAG_END_STREAM` across multi-DATA frames.
fn test_grpc_h2_large_multiframe_and_sni_ip_seam() {
    let rnd:   u8[32] = [0x11; 32];
    let pub_k: u8[32] = [0x22; 32];
    var ch_body: u8[..512] = [];
    wing::build_tls13_client_hello_payload(rnd, pub_k, "127.0.0.1", "h2", ch_body);
    var ch_hs: u8[..520] = [];
    ch_hs.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_hs, ch_body.len as u32);
    ch_hs.append(ch_body[..]);
    var sid:         u8[..32]  = [];
    var out_pub:     u8[32]    = [0; 32];
    var out_alpn:    u8[..32]  = [];
    var out_sni:     u8[..255] = [];
    var psk_resumed: bool      = false;
    var psk_secret:  u8[32]    = [0; 32];
    assert(wing::parse_client_hello_for_server_sni(
        ch_hs[..], "h2,http/1.1", sid, out_pub, out_alpn, out_sni, psk_resumed, psk_secret,
    ));
    assert(out_sni.len == 0);

    var enc = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var big_res = wing::Response { status_code: 200, .. };
    let _ = wing::append_header(big_res.headers, "content-type", "application/grpc");
    let _ = wing::append_header(big_res.trailers, "grpc-status", "0");
    for i in 20000 {
        let _ = i;
        big_res.body.push('A');
    }
    var out_frames: u8[..32768] = [];
    wing::emit_grpc_h2_response_frames(enc, 1, big_res, out_frames);
    var pos:              i64 = 0;
    var data_frame_count: i64 = 0;
    while pos + 9 <= out_frames.len {
        let fhdr, _, ok_fh = wire::parse_frame_header(out_frames[pos..pos + 9]);
        assert(ok_fh);
        if fhdr.frame_type == rfc::H2_FRAME_DATA {
            data_frame_count++;
            assert(fhdr.length <= rfc::H2_DEFAULT_MAX_FRAME_SIZE);
        }
        pos += 9 + (fhdr.length as i64);
    }
    assert(data_frame_count == 2);

    var disp = wing::GrpcServerDispatcher { .. };
    let _ = wing::register_unary(disp, "test.Echo", "Unary", 1);
    var hdec = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var henc = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var pending = wing::Request { .. };
    let _ = pending.method.try_set("POST");
    let _ = pending.url.try_set("/test.Echo/Unary");
    let _ = wing::append_header(pending.headers, "content-type", "application/grpc");
    var wire_out: u8[..65536] = [];
    let hdr_part1 = wire::WireFrameHeader { length: 5, frame_type: rfc::H2_FRAME_DATA, flags: 0, stream_id: 1 };
    let lpm_prefix: u8[5] = [0, 0, 0, 0, 4];
    assert(wing::handle_grpc_h2_wire_frame(-1, g_seam_server, disp, "127.0.0.1", hdec, henc, pending, hdr_part1, lpm_prefix[..], wire_out, seam_grpc_echo_handler));
    assert(wire_out.len == 0);
    let hdr_part2 = wire::WireFrameHeader { length: 4, frame_type: rfc::H2_FRAME_DATA, flags: rfc::H2_FLAG_END_STREAM, stream_id: 1 };
    assert(wing::handle_grpc_h2_wire_frame(-1, g_seam_server, disp, "127.0.0.1", hdec, henc, pending, hdr_part2, "PING", wire_out, seam_grpc_echo_handler));
    assert(wire_out.len > 0);

    // Seam 18: `tls_send_encrypted_record` must allocate `payload.len + 22` bytes (5-byte header + 1-byte inner type + 16-byte tag)
    let lfd_tls = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd_tls > 0);
    let tls_port = wing::tcp_getsockname_port(lfd_tls);
    let cfd_tls = wing::tcp_connect("127.0.0.1", tls_port, 200);
    let sfd_tls = wing::tcp_accept(lfd_tls, 200);
    assert(cfd_tls > 0 && sfd_tls > 0);
    let slot_t = wing::alloc_tls_cipher_slot();
    wing::g_tls_cipher_slots[slot_t as i64].cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    wing::g_tls_cipher_slots[slot_t as i64].key_len = 16;
    assert(wing::tls_send_encrypted_record(cfd_tls, slot_t, rfc::TLS_CONTENT_APPLICATION_DATA, "HELLO_TLS13"));
    wing::free_tls_cipher_slot(slot_t);
    wing::tcp_close(cfd_tls);
    wing::tcp_close(sfd_tls);
    wing::tcp_close(lfd_tls);
    print("SEAM_GRPC_H2_LARGE_AND_SNI_IP: OK");
}

// Seam 19, 20 & 21:
// - `run_client_preflight_stages` must pass canonical `parsed_initial.href` to `stage_client_cache_lookup`
//   so root URLs without trailing slash ("http://127.0.0.1:8080") match `stage_client_cache_store`.
// - `encode_h2_client_request` + `should_skip_h2_entry` + `H2ServerSession` must support RFC 8441
//   Extended CONNECT (`:protocol = websocket`) without duplicating `:method`/`:protocol` after
//   pseudo-headers, and `H2ServerSession` must preserve `:protocol`, `:scheme`, `:path`, `:authority`
//   on `req.headers` for `validate_h2_websocket_handshake`.
fn test_proxy_cache_h2_extended_connect_seams() {
    g_seam_session = wing::Client { .. };
    g_seam_session.virtual_clock_us = 0;
    g_seam_session.enable_cache = true;
    let parsed_root = core::new_url("http://127.0.0.1:18080");
    var req_root = wing::new_request("GET", "http://127.0.0.1:18080");
    var cached_resp = wing::Response { status_code: 200, .. };
    let _ = wing::append_header(cached_resp.headers, "Cache-Control", "max-age=60");
    let _ = wing::append_header(cached_resp.headers, "ETag", "\"v1\"");
    cached_resp.body.append("CACHED_ROOT_PAYLOAD");
    var ts = wing::CacheTimestamps { .. };
    let _ = wing::stage_client_cache_store(
        req_root, req_root.headers, parsed_root, "GET", cached_resp, ts, -1, g_seam_session.cache, g_seam_session.enable_cache,
    );

    let early_resp, early_err = wing::execute_request(g_seam_session, req_root);
    assert(wing::ok(early_err) && early_resp.status_code == 200);
    assert(early_resp.body[..] == "CACHED_ROOT_PAYLOAD");

    var ws_req = wing::Request { .. };
    wing::format_h2_websocket_request(ws_req, "/ws", "127.0.0.1:18080", "http", "chat");
    var ws_ctx = wing::RequestExecutionContext { .. };
    wing::copy_headers(ws_req.headers, ws_ctx.headers);
    let u_ws = core::new_url("http://127.0.0.1:18080/ws");
    var dt_cli = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var h2_wire: u8[..4096] = [];
    assert(wing::encode_h2_client_request("CONNECT", u_ws, false, ws_ctx, dt_cli, 1, false, h2_wire));

    var fhdr, _, ok_fh = wire::parse_frame_header(h2_wire[..9]);
    assert(ok_fh && fhdr.frame_type == rfc::H2_FRAME_HEADERS);
    var dt_srv = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var dec_pseudo = internal::H2PseudoHeaders { .. };
    var dec_map = wing::HeaderMap { .. };
    let dec_err = wire::decode_hpack_to_map(dt_srv, h2_wire[9..9 + (fhdr.length as i64)], dec_pseudo, dec_map);
    assert(dec_err == rfc::H2_ERR_NO_ERROR);
    assert(dec_pseudo.has_protocol && dec_pseudo.protocol[..] == "websocket");

    var st = internal::H2ServerStream { stream_id: 1, active: true, .. };
    assert(internal::apply_decoded_pseudo_to_stream(st, dec_pseudo));
    wing::append_all_headers(dec_map, st.headers);
    var srv_req = wing::new_request(st.method[..], st.path[..]);
    internal::copy_stream_headers_and_trailers(st, srv_req);
    assert(wing::validate_h2_websocket_request(srv_req));
    print("SEAM_PROXY_CACHE_H2_EXT_CONNECT: OK");
}

fn run_03_verify_module_seams_regress() {
    test_client_h2_trailers_and_incremental_drain();
    test_h3_query_and_trailers_seam();
    test_client_egress_pipeline_custom_order();
    test_server_tls_sni_extraction();
    test_tls_san_to_pool_coalescing();
    test_server_custom_stage_hook_seam();
    test_h2_server_flow_window_and_closed_stream_seams();
    test_h2_client_sliced_stream_recv_seam();
    test_h1_client_last_response_header_preserved_seam();
    test_grpc_h2_large_multiframe_and_sni_ip_seam();
    test_proxy_cache_h2_extended_connect_seams();
}

// CHECK: SEAM_H2_CLIENT_TRAILERS_DRAIN: OK
// CHECK-NEXT: SEAM_H3_QUERY_AND_TRAILERS: OK
// CHECK-NEXT: SEAM_CLIENT_EGRESS_STAGES_ORDER: OK
// CHECK-NEXT: SEAM_TLS_SERVER_SNI: OK
// CHECK-NEXT: SEAM_TLS_SAN_POOL_COALESCING: OK
// CHECK-NEXT: SEAM_SERVER_CUSTOM_STAGE_HOOK: OK
// CHECK-NEXT: SEAM_H2_FLOW_AND_CLOSED_STREAMS: OK
// CHECK-NEXT: SEAM_H2_CLIENT_SLICED_STREAM: OK
// CHECK-NEXT: SEAM_H1_LAST_RESPONSE_HEADER: OK
// CHECK-NEXT: SEAM_GRPC_H2_LARGE_AND_SNI_IP: OK
// CHECK-NEXT: SEAM_PROXY_CACHE_H2_EXT_CONNECT: OK

// ============================================================================
// 4. verify_readme_quickstart (4/12)
// ============================================================================
// CHECK: === [4/12] verify_readme_quickstart ===

// tests/lit/verify_readme_quickstart.goose
// Verification suite ensuring all README.md Quick Start snippets compile and execute correctly.
//

fn test_snippet_1_http_client() {
    var sess = wing::new_session("https://api.example.com") { s =>
        s.set_profile(wing::Profile.Wing);
        s.set_timeout_ms(5000);
        s.default_header("Accept", "application/json");
    };

    // Install mock route for offline CI execution
    wing::mock_route(sess, "GET", "https://api.example.com/v1/status", 200, "{\"status\":\"ok\"}");

    let res, err = sess.get("/v1/status");
    assert(err.ok());
    assert(res.is_success());
    assert(res.status_code == 200);
    assert(res.body[..] == "{\"status\":\"ok\"}");
    print("SNIPPET_1_CLIENT: OK");
}

fn test_snippet_2_http_server() {
    var server = wing::new_http_server("127.0.0.1", 8080);

    // Register routes with zero-allocation parameters
    server.add_get_route("/api/v1/users/{id}", 1);
    server.add_post_route("/api/v1/orders", 2);

    assert(server.port == 8080);
    print("SNIPPET_2_SERVER: OK");
}

fn test_snippet_3_websocket() {
    var hdr = wing::WsFrameHeader {
        fin:         true,
        opcode:      rfc::WS_OPCODE_TEXT,
        masked:      true,
        mask_key:    [0x12, 0x34, 0x56, 0x78],
        payload_len: 5,
    };

    var frame: u8[..64] = [];
    hdr.encode(frame);

    var payload: u8[..32] = [];
    payload.append("Hello");
    wing::mask_websocket_payload(payload[..], hdr.mask_key);
    frame.append(payload[..]);

    assert(frame.len > 0);
    print("SNIPPET_3_WEBSOCKET: OK");
}

fn run_04_verify_readme_quickstart() {
    test_snippet_1_http_client();
    test_snippet_2_http_server();
    test_snippet_3_websocket();

    // CHECK: SNIPPET_1_CLIENT: OK
    // CHECK: SNIPPET_2_SERVER: OK
    // CHECK: SNIPPET_3_WEBSOCKET: OK
    // CHECK: README_QUICKSTART: ALL PASS
    print("README_QUICKSTART: ALL PASS");
}

// ============================================================================
// 5. verify_wire_api (5/12)
// ============================================================================
// CHECK: === [5/12] verify_wire_api ===

// tests/lit/verify_wire_api.goose
// Verification of Vulkan-style zero-allocation wire command buffer recording,
// back-patching, and frame stream demuxing via wing::wire.
//

fn run_05_verify_wire_api() {
    print("=== WIRE_VULKAN_API_VERIFICATION ===");

    // 1. Storage and Command Buffer Initialization
    var cmd = wire::new_command_buffer();

    assert(cmd.buf.len == 0);
    assert(wire::available(cmd) == wire::WIRE_CMD_BUFFER_CAP);
    assert(!cmd.has_error);
    print("CMD_INIT: OK");

    // 2. Client Preface
    assert(wire::write_h2_preface(cmd));
    assert(cmd.buf.len == 24);
    print("CMD_PREFACE: OK");

    // 3. SETTINGS Frame (Stream 0)
    let s_list: wire::WireSetting[2] = [
        wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 65535),
    ];
    assert(wire::write_h2_settings(cmd, s_list[..]));
    print("CMD_SETTINGS: OK");

    // 4. WINDOW_UPDATE Frame (Stream 0)
    assert(wire::write_h2_window_update(cmd, 0, 1048576));
    print("CMD_WINDOW_UPDATE: OK");

    // 5. Dynamic HEADERS Frame with HPACK Back-Patching
    assert(wire::begin_h2_headers(cmd, 1, rfc::H2_FLAG_END_HEADERS));
    assert(wire::hpack_indexed(cmd, 2)); // :method: GET
    assert(wire::hpack_indexed(cmd, 7)); // :scheme: https
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/healthz"));
    assert(wire::hpack_literal_never_indexed(cmd, "x-api-key", "secret-test-token"));
    assert(wire::end_h2_headers(cmd));
    print("CMD_HEADERS_DYNAMIC: OK");

    // 6. RST_STREAM, PING, and DATA Frames
    assert(wire::write_h2_rst_stream(cmd, 3, 8)); // Cancel stream 3
    let ping_data: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    assert(wire::write_h2_ping(cmd, ping_data, false));

    let payload = "hello wire world";
    assert(wire::write_h2_data(cmd, 1, payload, true));
    print("CMD_DATA: OK");

    // 7. Verify Frame Stream Demux with WireH2FrameReader
    let wire_data = cmd.buf[..];
    assert(wire_data.len > 24);

    let frames_data = wire_data[24..];
    var reader = wire::new_wire_h2_frame_reader(frames_data);

    // Frame 1: SETTINGS
    assert(wire::has_next(reader));
    let f1, p1, ok1 = wire::next_frame(reader);
    assert(ok1 && f1.frame_type == rfc::H2_FRAME_SETTINGS && f1.length == 12 && p1.len == 12);

    // Frame 2: WINDOW_UPDATE
    assert(wire::has_next(reader));
    let f2, p2, ok2 = wire::next_frame(reader);
    assert(ok2 && f2.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && f2.length == 4 && p2.len == 4);

    // Frame 3: HEADERS
    assert(wire::has_next(reader));
    let f3, p3, ok3 = wire::next_frame(reader);
    assert(ok3 && f3.frame_type == rfc::H2_FRAME_HEADERS && f3.stream_id == 1 && f3.flags == rfc::H2_FLAG_END_HEADERS);
    assert(p3.len == (f3.length as i64));

    // Frame 4: RST_STREAM
    assert(wire::has_next(reader));
    let f4, p4, ok4 = wire::next_frame(reader);
    assert(ok4 && f4.frame_type == rfc::H2_FRAME_RST_STREAM && f4.stream_id == 3 && f4.length == 4);

    // Frame 5: PING
    assert(wire::has_next(reader));
    let f5, p5, ok5 = wire::next_frame(reader);
    assert(ok5 && f5.frame_type == rfc::H2_FRAME_PING && f5.length == 8 && p5.len == 8);

    // Frame 6: DATA
    assert(wire::has_next(reader));
    let f6, p6, ok6 = wire::next_frame(reader);
    assert(ok6 && f6.frame_type == rfc::H2_FRAME_DATA && f6.stream_id == 1 && f6.flags == rfc::H2_FLAG_END_STREAM);
    assert(p6 == payload);

    // No further frames
    assert(!wire::has_next(reader));
    print("STREAM_DEMUX_VERIFIED: OK");

    // 8. Direct Frame Encoders Verification
    var direct_buf: u8[..512] = [];
    assert(wire::encode_settings_frame(s_list[..], direct_buf));
    assert(wire::encode_window_update_frame(0, 4096, direct_buf));
    assert(wire::encode_priority_update_frame(1, 2, true, direct_buf));
    assert(wire::encode_rst_stream_frame(1, 1, direct_buf));
    assert(wire::encode_ping_frame(ping_data, true, direct_buf));
    assert(wire::encode_data_frame(1, "test", false, direct_buf));
    assert(direct_buf.len > 0);

    var custom_cmd = wire::new_command_buffer();
    let custom_hdr = wire::WireFrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    assert(wire::write_h2_frame_header(custom_cmd, custom_hdr));
    assert(custom_cmd.buf.len == 9);
    print("DIRECT_ENCODERS: OK");

    // 9. Direct HPACK Encoders and String Decoder Verification
    var hpack_raw: u8[..256] = [];
    assert(wire::hpack_encode_indexed(hpack_raw, 2));
    assert(wire::hpack_encode_literal_without_indexing(hpack_raw, "custom-header", "custom-val"));
    assert(wire::hpack_encode_literal_never_indexed(hpack_raw, "secret", "dont-index"));
    assert(hpack_raw.len > 0);

    var dec_offset: u64      = 0;
    var str_sample: u8[..64] = [];
    assert(wire::hpack_encode_string(str_sample, "decoded_target"));
    var dec_out: u8[..64] = [];
    assert(wire::hpack_decode_string(str_sample[..], dec_offset, dec_out));
    assert(dec_out == "decoded_target");
    print("HPACK_CODECS: OK");

    // 10. WireQueue Lifecycle and Invariants
    let dev_cfg = wire::WireDeviceConfig { .. };
    var queue = wire::new_wire_queue(dev_cfg);
    assert(!queue.is_connected);
    assert(queue.bytes_sent == 0);

    // Unconnected queue rejects submission safely
    let _, sub_slice_ok = wire::submit_slice(queue, "dummy");
    assert(!sub_slice_ok);

    var rx_dummy: u8[16] = [0; 16];
    let _, poll_ok = wire::poll_recv(queue, rx_dummy[..]);
    assert(!poll_ok);

    let connect_ok = wire::connect_wire_queue(queue, "127.0.0.1", 1, 10);
    assert(!connect_ok || queue.is_connected);
    wire::close_wire_queue(queue);
    assert(!queue.is_connected);
    print("QUEUE_LIFECYCLE: OK");

    // 11. Capacity Overflow Safety Guard Test
    var of_cmd = wire::new_command_buffer();
    var chunk: u8[1024] = [0; 1024];
    for i in 0..16 {
        assert(wire::write_raw(of_cmd, chunk[..]));
    }
    assert(of_cmd.buf.len == wire::WIRE_CMD_BUFFER_CAP);
    // Writing beyond capacity triggers guard
    assert(!wire::write_u8(of_cmd, 0xFF));
    assert(of_cmd.has_error);
    print("OVERFLOW_GUARD_TRIGGERED: OK");
}

// CHECK: === WIRE_VULKAN_API_VERIFICATION ===
// CHECK: CMD_INIT: OK
// CHECK: CMD_PREFACE: OK
// CHECK: CMD_SETTINGS: OK
// CHECK: CMD_WINDOW_UPDATE: OK
// CHECK: CMD_HEADERS_DYNAMIC: OK
// CHECK: CMD_DATA: OK
// CHECK: STREAM_DEMUX_VERIFIED: OK
// CHECK: DIRECT_ENCODERS: OK
// CHECK: HPACK_CODECS: OK
// CHECK: QUEUE_LIFECYCLE: OK
// CHECK: OVERFLOW_GUARD_TRIGGERED: OK

// ============================================================================
// 6. verify_wire_benchmarks (6/12)
// ============================================================================
// CHECK: === [6/12] verify_wire_benchmarks ===

// tests/lit/verify_wire_benchmarks.goose
// Verification of Zero-Allocation Wire Primitives & Microbenchmark Latency Budgets.
// Benchmarks AVX2/SWAR CRLFCRLF scanner, TLS record header parser,
// gRPC LPM decoder, and chunked transfer FSM decoder under strict latency ceilings.
//

fn bench_crlfcrlf_throughput() {
    let req:   const u8[:] = "GET /v1/telemetry HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: wing/1.0\r\nAccept: */*\r\n\r\n";
    let iters: i64         = 5000;

    // Warm-up
    for _ in 100 {
        let _ = core::fast_find_crlfcrlf(req);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        let off = core::fast_find_crlfcrlf(req);
        assert(off > 0);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 500);
    print("BENCH_CRLFCRLF: OK");
}

fn bench_tls_record_parsing() {
    let raw_rec: u8[5] = [0x17, 0x03, 0x03, 0x01, 0x00]; // 256 bytes payload
    let iters:   i64   = 5000;

    for _ in 100 {
        let _ = wing::parse_tls_record_header(raw_rec[..]);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        let ct, _, len, _, ok = wing::parse_tls_record_header(raw_rec[..]);
        assert(ok && ct == 0x17 && len == 256);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 300);
    print("BENCH_TLS_HEADER: OK");
}

fn bench_grpc_lpm_decoding() {
    let raw_lpm: u8[13] = [0x00, 0x00, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
    let iters:   i64    = 5000;

    for _ in 100 {
        let _ = wing::decode_grpc_lpm_slice(raw_lpm[..], 0);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        let payload_slice, compressed, consumed, ok = wing::decode_grpc_lpm_slice(raw_lpm[..], 0);
        assert(ok && !compressed && consumed == 13 && payload_slice.len == 8);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 300);
    print("BENCH_GRPC_LPM: OK");
}

fn bench_chunk_fsm_feed() {
    let raw_chunk: const u8[:] = "A\r\n0123456789\r\n";
    let iters:     i64         = 5000;

    for _ in 100 {
        var dec = internal::new_chunk_fsm_decoder();
        let st_w, _, _ = internal::chunk_fsm_feed(dec, raw_chunk);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        var dec = internal::new_chunk_fsm_decoder();
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw_chunk);
        var is_chunk = false;
        match st {
            YieldChunk => { is_chunk = true; },
            Complete => {},
            NeedMore => {},
            Error => {},
        }
        assert(is_chunk && consumed > 0 && chunk.len == 10);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 500);
    print("BENCH_CHUNK_FSM: OK");
}

fn run_06_verify_wire_benchmarks() {
    print("=== RUNNING ZERO-ALLOC WIRE BENCHMARKS ===");
    bench_crlfcrlf_throughput();
    bench_tls_record_parsing();
    bench_grpc_lpm_decoding();
    bench_chunk_fsm_feed();
    print("ZERO-ALLOC WIRE BENCHMARKS COMPLETE: ALL BUDGETS PASSED");
}

// CHECK: === RUNNING ZERO-ALLOC WIRE BENCHMARKS ===
// CHECK: BENCH_CRLFCRLF: OK
// CHECK: BENCH_TLS_HEADER: OK
// CHECK: BENCH_GRPC_LPM: OK
// CHECK: BENCH_CHUNK_FSM: OK
// CHECK: ZERO-ALLOC WIRE BENCHMARKS COMPLETE: ALL BUDGETS PASSED

// ============================================================================
// 7. verify_wire_bounds (7/12)
// ============================================================================
// CHECK: === [7/12] verify_wire_bounds ===

// Verification of HTTP/2 wire frame bounds and RFC invariants (RFC 9113, RFC 9218).

fn run_07_verify_wire_bounds() {
    print("=== VERIFY_WIRE_BOUNDS ===\n");

    var buf: u8[..256] = [];

    // Case 1: DATA frame MUST reject stream_id = 0 (RFC 9113 Section 6.1)
    let data_zero_sid = wire::encode_data_frame(0, "payload", true, buf);
    assert(!data_zero_sid);
    print("DATA_ZERO_SID_REJECTED: OK\n");
    // CHECK: DATA_ZERO_SID_REJECTED: OK

    // Case 2: RST_STREAM frame MUST reject stream_id = 0 (RFC 9113 Section 6.4)
    buf.clear();
    let rst_zero_sid = wire::encode_rst_stream_frame(0, 1, buf);
    assert(!rst_zero_sid);
    print("RST_ZERO_SID_REJECTED: OK\n");
    // CHECK: RST_ZERO_SID_REJECTED: OK

    // Case 3: WINDOW_UPDATE frame MUST reject increment = 0 (RFC 9113 Section 6.9)
    buf.clear();
    let win_zero_inc = wire::encode_window_update_frame(1, 0, buf);
    assert(!win_zero_inc);
    print("WINDOW_UPDATE_ZERO_INC_REJECTED: OK\n");
    // CHECK: WINDOW_UPDATE_ZERO_INC_REJECTED: OK

    // Case 4: PRIORITY_UPDATE frame MUST reject prioritized_stream_id = 0 (RFC 9218 Section 7.1)
    buf.clear();
    let prio_zero_psid = wire::encode_priority_update_frame(0, 0, false, buf);
    assert(!prio_zero_psid);
    print("PRIORITY_UPDATE_ZERO_PSID_REJECTED: OK\n");
    // CHECK: PRIORITY_UPDATE_ZERO_PSID_REJECTED: OK

    // Case 5: parse_frame_header returns error code 0 (Incomplete), not 1 (PROTOCOL_ERROR), on buf.len < 9
    let short_buf: const u8[:] = "\x00\x00\x04\x00";
    let hdr, err_code, ok = wire::parse_frame_header(short_buf);
    assert(!ok);
    assert(err_code == 0);
    print("SHORT_HEADER_NO_PROTOCOL_ERROR: OK\n");
    // CHECK: SHORT_HEADER_NO_PROTOCOL_ERROR: OK

    // Case 6 (F-WIRE-001): encode_h1_response fails closed and rolls back on small buffer overflow
    var small_h1: u8[..32] = [];
    small_h1.append("PREFIX");
    var h1_hdrs = wing::HeaderMap { .. };
    wing::append_header(h1_hdrs, "X-Long-Header", "0123456789abcdef0123456789abcdef");
    assert(!wire::encode_h1_response(200, "OK", "goose-wing", h1_hdrs, "hello", false, small_h1));
    assert(small_h1[..] == "PREFIX");
    assert(!wire::encode_h1_request(
        "GET", "/path", "example.com", h1_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, small_h1,
    ));
    assert(small_h1[..] == "PREFIX");
    print("H1_RESPONSE_TRANSACTIONAL_BOUNDS: OK\n");
    // CHECK: H1_RESPONSE_TRANSACTIONAL_BOUNDS: OK

    // Case 7 (F-WIRE-002): Host header rejects control bytes/spaces & decode_h1_response_head returns MalformedStatusLine
    var host_out: u8[..128] = [];
    let empty_hdrs = wing::HeaderMap { .. };
    assert(!wire::encode_h1_request(
        "GET", "/", "bad host.example.com", empty_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, host_out,
    ));
    assert(!wire::encode_h1_request(
        "GET", "/", "bad\thost.example.com", empty_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, host_out,
    ));
    var bad_status: u16 = 0;
    var parsed_hdrs = wing::HeaderMap { .. };
    let _, bad_st_err = wire::decode_h1_response_head("HTTP/2.0 200 OK\r\n\r\n", bad_status, parsed_hdrs);
    assert(bad_st_err == wing::HeaderParseError.MalformedStatusLine);
    print("H1_HOST_AND_STATUS_LINE_BOUNDS: OK\n");
    // CHECK: H1_HOST_AND_STATUS_LINE_BOUNDS: OK

    // Case 8 (F-WIRE-003): H2 stream_id MSB (0x80000000), >24-bit length, urgency > 7, transactional rollback, and CONTINUATION
    buf.clear();
    assert(!wire::encode_data_frame(0x80000000, "x", false, buf));
    assert(!wire::encode_rst_stream_frame(0x80000000, 1, buf));
    assert(!wire::encode_priority_update_frame(0x80000000, 0, false, buf));
    assert(!wire::encode_window_update_frame(0x80000000, 1, buf));
    assert(!wire::encode_priority_update_frame(1, 8, false, buf));
    let ovf_hdr = wire::WireFrameHeader {
        length:     0x01000000,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      0,
        stream_id:  1,
    };
    assert(!wire::encode_frame_header(ovf_hdr, buf));
    var tight_h2: u8[..12] = [];
    tight_h2.append("AB"); // 10 bytes left: fits 9-byte header, but not 4-byte payload
    assert(!wire::encode_window_update_frame(0, 1024, tight_h2));
    assert(tight_h2[..] == "AB");
    assert(!wire::encode_rst_stream_frame(1, 1, tight_h2));
    assert(tight_h2[..] == "AB");
    assert(!wire::encode_data_frame(1, "1234", false, tight_h2));
    assert(tight_h2[..] == "AB");
    var cont_dt = internal::new_dynamic_table(4096);
    var cont_pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var cont_hdrs = wing::HeaderMap { .. };
    wing::append_header(cont_hdrs, "x-cont-test", "0123456789abcdef0123456789abcdef");
    var cont_out: u8[..256] = [];
    assert(wire::encode_h2_headers_frame_from_map(cont_dt, 1, cont_pseudo, cont_hdrs, true, cont_out, 16));
    var f_reader = wire::new_wire_h2_frame_reader(cont_out[..]);
    let fh1, _, ok_f1 = wire::next_frame(f_reader);
    let fh2, _, ok_f2 = wire::next_frame(f_reader);
    assert(ok_f1 && fh1.frame_type == rfc::H2_FRAME_HEADERS && (fh1.flags & rfc::H2_FLAG_END_HEADERS) == 0);
    assert(ok_f2 && fh2.frame_type == rfc::H2_FRAME_CONTINUATION);
    print("H2_FRAME_BOUNDS_AND_CONTINUATION: OK\n");
    // CHECK: H2_FRAME_BOUNDS_AND_CONTINUATION: OK

    // Case 9 (F-WIRE-004 & F-WIRE-005): HPACK & QPACK map overflow and invalid status rejection
    var fresh_dt = internal::new_dynamic_table(4096);
    var small_hpack: u8[..16] = [];
    small_hpack.append("XY");
    assert(!wire::hpack_encode_literal_without_indexing(small_hpack, "x-custom-name", "long-value-12345"));
    assert(small_hpack[..] == "XY");
    assert(!wire::encode_hpack_from_map(fresh_dt, cont_pseudo, cont_hdrs, small_hpack, false));
    assert(small_hpack[..] == "XY");
    var bad_h2_pseudo = internal::H2PseudoHeaders { has_status: true, status: 0, .. };
    var tmp_hpack: u8[..64] = [];
    assert(!wire::encode_hpack_from_map(cont_dt, bad_h2_pseudo, empty_hdrs, tmp_hpack, false));
    var qp_tbl = internal::new_qpack_table(4096);
    var bad_h3_pseudo = internal::H3PseudoHeaders { has_status: true, status: 0, .. };
    var qp_enc: u8[..64] = [];
    var qp_frm: u8[..64] = [];
    assert(!wire::encode_h3_headers_from_map(qp_tbl, 0, bad_h3_pseudo, empty_hdrs, qp_enc, qp_frm));
    var ok_h3_pseudo = internal::H3PseudoHeaders { has_status: true, status: 200, .. };
    var tiny_enc: u8[..4] = [];
    tiny_enc.append("E");
    var tiny_frm: u8[..16] = [];
    tiny_frm.append("F");
    assert(!wire::encode_h3_headers_from_map(qp_tbl, 0, ok_h3_pseudo, cont_hdrs, tiny_enc, tiny_frm));
    assert(tiny_enc[..] == "E");
    assert(tiny_frm[..] == "F");
    print("HPACK_QPACK_MAP_BOUNDS: OK\n");
    // CHECK: HPACK_QPACK_MAP_BOUNDS: OK

    // Case 10 (F-WIRE-006 & F-WIRE-007): Pool arena slot 0 protection, double-free guard, and submit state checks
    let inst = wire::WireInstance { .. };
    var phys: wire::WirePhysicalDevice[..4] = [];
    let _ = wire::enumerate_physical_devices(inst, phys);
    let dev_info = wire::WireDeviceCreateInfo { .. };
    var dev, _ = wire::create_wire_device(phys[0], dev_info);
    let pool_info = wire::WireCommandPoolCreateInfo { .. };
    var pool, _ = wire::create_command_pool(dev, pool_info);
    var pcmd1, _ = wire::allocate_command_buffer(pool);
    var pcmd2, _ = wire::allocate_command_buffer(pool);
    let begin_info = wire::WireCommandBufferBeginInfo { .. };
    let _ = wire::begin_command_buffer(pcmd1, begin_info);
    assert(wire::write_h2_preface(pcmd1));
    let _ = wire::end_command_buffer(pcmd1);
    let slice1, ok_c1 = wire::commit_command_buffer_to_arena(pool, pcmd1);
    assert(ok_c1 && slice1 == rfc::H2_CLIENT_PREFACE);
    var standalone = wire::new_command_buffer();
    assert(wire::write_raw(standalone, "CORRUPT_SLOT_ZERO_______"));
    let _, ok_standalone_commit = wire::commit_command_buffer_to_arena(pool, standalone);
    assert(!ok_standalone_commit);
    assert(pool.arena[..24] == rfc::H2_CLIENT_PREFACE);
    wire::free_command_buffer(pool, pcmd2);
    wire::free_command_buffer(pool, pcmd2); // double-free must not decrement allocated_count to 0
    assert(pool.allocated_count == 1 && pool.arena.len >= 24);
    var q = wire::get_device_queue(dev, 0, 0);
    q.driver = wire::WireDriverKind.Mock;
    q.is_connected = true;
    let _, ok_sub_freed = wire::submit(q, pcmd2);
    assert(!ok_sub_freed);
    print("POOL_AND_SUBMIT_STATE_BOUNDS: OK\n");
    // CHECK: POOL_AND_SUBMIT_STATE_BOUNDS: OK

    print("ALL_WIRE_BOUNDS_VERIFIED: OK\n");
    // CHECK: ALL_WIRE_BOUNDS_VERIFIED: OK
}

// ============================================================================
// 8. verify_wire_framing (8/12)
// ============================================================================
// CHECK: === [8/12] verify_wire_framing ===

// tests/lit/verify_wire_framing.goose
// Verification of wire framing primitives: gRPC LPM, TLS record headers, and SIMD CRLFCRLF scanning.
//

fn decode_grpc_lpm_len(buf: const u8[:]) -> i32 {
    let payload_slice, _, _, ok = wing::decode_grpc_lpm_slice(buf, 0);
    guard ok else { return -1; }
    return payload_slice.len as! i32;
}

fn validate_tls_record_header(buf: const u8[:]) -> i32 {
    let ctype, _, _, alert, ok = wing::parse_tls_record_header(buf);
    guard ok else {
        if alert == wing::TlsAlert.RecordOverflow {
            return 22;
        }
        return -1;
    }
    return ctype;
}

fn verify_h1_wire_parsers() {
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
    let req_err = wing::parse_request_headers("\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n", req_map);
    assert(req_err == wing::HeaderParseError.None && wing::get_header(req_map, "host") == "example.com");

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

fn run_08_verify_wire_framing() {
    var grpc_raw: u8[>..] = [];
    assert(wire_kit::parse_hex("000000000B68656C6C6F20776F726C64", grpc_raw));
    let grpc_len = decode_grpc_lpm_len(grpc_raw[..]);
    assert(grpc_len == 11);
    assert(grpc_raw[5] == 104); // 'h'
    assert(grpc_raw[15] == 100); // 'd'
    print("GRPC_LPM_LEN: ", grpc_len);

    var tls_raw: u8[>..] = [];
    assert(wire_kit::parse_hex("1703030010", tls_raw));
    let tls_res = validate_tls_record_header(tls_raw[..]);
    assert(tls_res == 23); // Application Data
    print("TLS_RECORD_TYPE: ", tls_res);

    var tls_overflow: u8[>..] = [];
    assert(wire_kit::parse_hex("1703034101", tls_overflow));
    let tls_over_res = validate_tls_record_header(tls_overflow[..]);
    assert(tls_over_res == 22); // Record overflow alert
    print("TLS_OVERFLOW_ALERT: ", tls_over_res);

    let http_msg = "POST /submit HTTP/1.1\r\nContent-Length: 0\r\n\r\nBODY";
    let crlf_off = core::fast_find_crlfcrlf(http_msg);
    assert(crlf_off == 40);
    print("CRLFCRLF_OFFSET: ", crlf_off);

    let key: u8[16] = [0; 16];
    let iv:  u8[12] = [0; 12];
    var sealed: u8[64] = [0; 64];
    let sealed_len, seal_alert, ok_seal = wing::tls_record_seal_aes128_gcm_into(
        key, iv, 0, rfc::TLS_CONTENT_APPLICATION_DATA, "ping", sealed[..],
    );
    assert(ok_seal && seal_alert == wing::TlsAlert.CloseNotify && sealed_len == 26);
    var dec: u8[64] = [0; 64];
    let dec_len, inner_t, _, ok_dec = wing::tls_record_decrypt_aes128_gcm_into(
        key, iv, 0, sealed[..5], sealed[5..26], dec[..],
    );
    assert(ok_dec && dec_len == 4 && inner_t == rfc::TLS_CONTENT_APPLICATION_DATA && dec[..4] == "ping");
    print("TLS_SEAL_ROUNDTRIP_LEN: ", dec_len);
    verify_h1_wire_parsers();
}

// CHECK: GRPC_LPM_LEN: 11
// CHECK: TLS_RECORD_TYPE: 23
// CHECK: TLS_OVERFLOW_ALERT: 22
// CHECK: CRLFCRLF_OFFSET: 40
// CHECK: TLS_SEAL_ROUNDTRIP_LEN: 4
// CHECK: H1_WIRE_PARSERS: OK

// ============================================================================
// 9. verify_wire_hierarchy (9/12)
// ============================================================================
// CHECK: === [9/12] verify_wire_hierarchy ===

fn test_wire_result() {
    let ok_res = wire::WireResult.Success;
    let err_res = wire::WireResult.ErrorDeviceLost;

    if wire::is_success(ok_res) {
        print("OK_RES_SUCCESS: 1\n");
    }
    if !wire::is_error(ok_res) {
        print("OK_RES_NOT_ERROR: 1\n");
    }
    if wire::is_error(err_res) {
        print("ERR_RES_IS_ERROR: 1\n");
    }
}

fn test_device_hierarchy() {
    let inst = wire::WireInstance { .. };
    var phys_devs: wire::WirePhysicalDevice[..4] = [];
    let enum_res = wire::enumerate_physical_devices(inst, phys_devs);
    if wire::is_success(enum_res) && phys_devs.len == 1 {
        print("ENUM_PHYSICAL_DEV_OK: 1\n");
    }

    let dev_info = wire::WireDeviceCreateInfo {
        config: wire::WireDeviceConfig { .. },
        enabled_features: wire::WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     false,
            hardware_tls:      false,
            raw_frames:        true,
        },
    };

    var dev, create_res = wire::create_wire_device(phys_devs[0], dev_info);
    if wire::is_success(create_res) && dev.is_active {
        print("CREATE_WIRE_DEVICE_OK: 1\n");
    }

    test_command_pool(dev);
    test_pipeline(dev);
    test_sync_primitives(dev);
    test_queue_batch_submit(dev);

    wire::destroy_wire_device(dev);
    if !dev.is_active {
        print("DESTROY_WIRE_DEVICE_OK: 1\n");
    }
}

fn test_command_pool(dev: const wire::WireDevice&) {
    let pool_info = wire::WireCommandPoolCreateInfo {
        flags:              wire::WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        queue_family_index: 0,
    };
    var pool, pool_res = wire::create_command_pool(dev, pool_info);
    if wire::is_success(pool_res) && pool.is_valid {
        print("CREATE_COMMAND_POOL_OK: 1\n");
    }

    let reset_res = wire::reset_command_pool(pool, wire::WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT);
    if wire::is_success(reset_res) {
        print("RESET_COMMAND_POOL_OK: 1\n");
    }

    test_cmd_buffer_fsm(pool);

    wire::trim_command_pool(pool);
    print("TRIM_COMMAND_POOL_OK: 1\n");

    wire::destroy_command_pool(pool);
    if !pool.is_valid {
        print("DESTROY_COMMAND_POOL_OK: 1\n");
    }
}

fn test_cmd_buffer_fsm(pool: wire::WireCommandPool&) {
    var cmd, alloc_res = wire::allocate_command_buffer(pool);
    if wire::is_success(alloc_res) && cmd.state == wire::WireCommandBufferState.Initial {
        print("ALLOC_CMD_BUF_OK: 1\n");
    }

    let begin_info = wire::WireCommandBufferBeginInfo {
        flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    let begin_res = wire::begin_command_buffer(cmd, begin_info);
    if wire::is_success(begin_res) && cmd.state == wire::WireCommandBufferState.Recording {
        print("BEGIN_CMD_BUF_OK: 1\n");
    }

    // 24-bit overflow test (BUG-09)
    let ovf_24 = wire::write_u24_be(cmd, 0x01000000);
    if !ovf_24 && cmd.has_error {
        print("U24_OVERFLOW_GUARD_OK: 1\n");
    }

    // Reset buffer for further clean recording
    wire::reset_command_buffer(cmd, 0);
    wire::begin_command_buffer(cmd, begin_info);

    // Dynamic headers interleave protection (BUG-04 & BUG-17)
    assert(wire::begin_h2_headers(cmd, 1, rfc::H2_FLAG_END_HEADERS));
    assert(cmd.state == wire::WireCommandBufferState.RecordingHeaders);

    // Attempting frame write inside headers block must fail (BUG-17)
    let ping_data: u8[8] = [0; 8];
    let interleave_res = wire::write_h2_ping(cmd, ping_data, false);
    if !interleave_res && cmd.has_error {
        print("HEADERS_INTERLEAVE_GUARD_OK: 1\n");
    }

    // Reset and complete clean recording
    wire::reset_command_buffer(cmd, 0);
    wire::begin_command_buffer(cmd, begin_info);
    assert(wire::write_h2_preface(cmd));
    let end_res = wire::end_command_buffer(cmd);
    if wire::is_success(end_res) && cmd.state == wire::WireCommandBufferState.Executable {
        print("END_CMD_BUF_OK: 1\n");
    }

    wire::free_command_buffer(pool, cmd);
    if cmd.state == wire::WireCommandBufferState.Invalid {
        print("FREE_CMD_BUF_OK: 1\n");
    }
}

fn test_pipeline(dev: const wire::WireDevice&) {
    let pipe_info = wire::WirePipelineCreateInfo {
        bind_point: wire::WirePipelineBindPoint.Transmit,
        layout: wire::WirePipelineLayout {
            max_frame_size: 16384,
            push_constants: [],
        },
        flags: 0,
    };
    var pipe, pipe_res = wire::create_wire_pipeline(dev, pipe_info);
    if wire::is_success(pipe_res) && pipe.is_valid {
        print("CREATE_WIRE_PIPELINE_OK: 1\n");
    }

    var cmd = wire::new_command_buffer();
    let bind_res = wire::cmd_bind_pipeline(cmd, wire::WirePipelineBindPoint.Transmit, pipe);
    if wire::is_success(bind_res) {
        print("BIND_WIRE_PIPELINE_OK: 1\n");
    }

    wire::destroy_wire_pipeline(pipe);
    if !pipe.is_valid {
        print("DESTROY_WIRE_PIPELINE_OK: 1\n");
    }
}

fn test_sync_primitives(dev: const wire::WireDevice&) {
    // 1. Fence test
    let fence_info = wire::WireFenceCreateInfo {
        flags: wire::WIRE_FENCE_CREATE_SIGNALED_BIT,
    };
    var fence, f_res = wire::create_wire_fence(dev, fence_info);
    if wire::is_success(f_res) && fence.is_valid {
        print("CREATE_WIRE_FENCE_OK: 1\n");
    }
    let wait_res = wire::wait_for_wire_fence(fence, 1000);
    if wire::is_success(wait_res) {
        print("WAIT_WIRE_FENCE_OK: 1\n");
    }
    let status_res = wire::get_wire_fence_status(fence);
    if wire::is_success(status_res) {
        print("STATUS_WIRE_FENCE_OK: 1\n");
    }
    let reset_res = wire::reset_wire_fence(fence);
    if wire::is_success(reset_res) && fence.status == wire::WireFenceStatus.Unsignaled {
        print("RESET_WIRE_FENCE_OK: 1\n");
    }
    wire::destroy_wire_fence(fence);
    if !fence.is_valid {
        print("DESTROY_WIRE_FENCE_OK: 1\n");
    }

    // 2. Semaphore test
    let sem_info = wire::WireSemaphoreCreateInfo {
        semaphore_type: wire::WireSemaphoreType.Timeline,
        initial_value:  0,
    };
    var sem, sem_res = wire::create_wire_semaphore(dev, sem_info);
    if wire::is_success(sem_res) && sem.is_valid {
        print("CREATE_WIRE_SEMAPHORE_OK: 1\n");
    }
    wire::signal_wire_semaphore(sem, 42);
    let sem_wait = wire::wait_wire_semaphore(sem, 42);
    if wire::is_success(sem_wait) {
        print("WAIT_WIRE_SEMAPHORE_OK: 1\n");
    }
    wire::destroy_wire_semaphore(sem);
    if !sem.is_valid {
        print("DESTROY_WIRE_SEMAPHORE_OK: 1\n");
    }
}

fn test_queue_batch_submit(dev: const wire::WireDevice&) {
    var q = wire::get_device_queue(dev, 0, 0);
    q.driver = wire::WireDriverKind.Mock;
    q.is_connected = true;

    var cmd1 = wire::new_command_buffer();
    assert(wire::write_h2_preface(cmd1));

    var cmd2 = wire::new_command_buffer();
    let s_list: wire::WireSetting[1] = [
        wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 0),
    ];
    assert(wire::write_h2_settings(cmd2, s_list[..]));

    let batch: wire::WireCommandBuffer[2] = [cmd1, cmd2];
    let submit_info = wire::WireSubmitInfo {
        stage_mask:       wire::WIRE_PIPELINE_STAGE_ALL_COMMANDS,
        wait_semaphore:   0,
        signal_semaphore: 0,
        bytes_submitted:  0,
    };

    let fence_info = wire::WireFenceCreateInfo { flags: 0 };
    var fence, f_res = wire::create_wire_fence(dev, fence_info);
    assert(wire::is_success(f_res));

    let sent_bytes, sub_res = wire::queue_submit_batch(q, batch[..], submit_info, fence);
    if wire::is_success(sub_res) && sent_bytes > 0 && fence.status == wire::WireFenceStatus.Signaled {
        print("QUEUE_SUBMIT_BATCH_OK: 1\n");
    }

    wire::close_wire_queue(q);
    if q.fd == -1 && !q.is_connected {
        print("CLOSE_WIRE_QUEUE_FD_RESET_OK: 1\n");
    }
}

fn run_09_verify_wire_hierarchy() {
    // CHECK: OK_RES_SUCCESS: 1
    // CHECK: OK_RES_NOT_ERROR: 1
    // CHECK: ERR_RES_IS_ERROR: 1
    // CHECK: ENUM_PHYSICAL_DEV_OK: 1
    // CHECK: CREATE_WIRE_DEVICE_OK: 1
    // CHECK: CREATE_COMMAND_POOL_OK: 1
    // CHECK: RESET_COMMAND_POOL_OK: 1
    // CHECK: ALLOC_CMD_BUF_OK: 1
    // CHECK: BEGIN_CMD_BUF_OK: 1
    // CHECK: U24_OVERFLOW_GUARD_OK: 1
    // CHECK: HEADERS_INTERLEAVE_GUARD_OK: 1
    // CHECK: END_CMD_BUF_OK: 1
    // CHECK: FREE_CMD_BUF_OK: 1
    // CHECK: TRIM_COMMAND_POOL_OK: 1
    // CHECK: DESTROY_COMMAND_POOL_OK: 1
    // CHECK: CREATE_WIRE_PIPELINE_OK: 1
    // CHECK: BIND_WIRE_PIPELINE_OK: 1
    // CHECK: DESTROY_WIRE_PIPELINE_OK: 1
    // CHECK: CREATE_WIRE_FENCE_OK: 1
    // CHECK: WAIT_WIRE_FENCE_OK: 1
    // CHECK: STATUS_WIRE_FENCE_OK: 1
    // CHECK: RESET_WIRE_FENCE_OK: 1
    // CHECK: DESTROY_WIRE_FENCE_OK: 1
    // CHECK: CREATE_WIRE_SEMAPHORE_OK: 1
    // CHECK: WAIT_WIRE_SEMAPHORE_OK: 1
    // CHECK: DESTROY_WIRE_SEMAPHORE_OK: 1
    // CHECK: QUEUE_SUBMIT_BATCH_OK: 1
    // CHECK: CLOSE_WIRE_QUEUE_FD_RESET_OK: 1
    // CHECK: DESTROY_WIRE_DEVICE_OK: 1
    test_wire_result();
    test_device_hierarchy();
}

// ============================================================================
// 10. verify_wire_loopback (10/12)
// ============================================================================
// CHECK: === [10/12] verify_wire_loopback ===

// tests/lit/verify_wire_loopback.goose
// End-to-end in-memory wire loopback verification for HTTP/2, QUIC, and HTTP/3.
// Validates pure raw wire serialization, bidirectional state machine exchange,
// and zero-allocation parsing without synthetic mock struct injection.
//

// Helper to encode a complete client HEADERS frame using HPACK
fn encode_client_request_headers<B>(
    dt:         internal::DynamicTable&,
    stream_id:  u32,
    method:     const u8[:],
    path:       const u8[:],
    scheme:     const u8[:],
    authority:  const u8[:],
    end_stream: bool,
    out:        B&,
) {
    var hpack_block: u8[..512] = [];
    internal::encode_hpack_field(dt, hpack_block, ":method", method, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hpack_block, ":path", path, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hpack_block, ":scheme", scheme, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hpack_block, ":authority", authority, internal::HpackIndexing.Incremental, false);

    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if end_stream {
        flags |= rfc::H2_FLAG_END_STREAM;
    }
    let hdr = internal::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hpack_block[..]);
}

// 1. HTTP/2 Full Wire Loopback:
// Client formats Preface + SETTINGS + HEADERS -> Server ingests, dispatches via pipeline -> Server emits SETTINGS + Response HEADERS
fn test_h2_wire_loopback() {
    var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/api/ping", 200);

    // Client encodes raw wire stream
    var client_to_server: u8[..1024] = [];
    client_to_server.append(rfc::H2_CLIENT_PREFACE[..]);

    // Client empty SETTINGS frame
    let set_hdr = internal::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    internal::encode_frame_header_to(set_hdr, client_to_server);

    // Client GET /api/ping request on stream 1
    encode_client_request_headers(
        client_hpack, 1, "GET", "/api/ping", "https", "example.com", true, client_to_server,
    );

    // Server ingests client bytes and generates server wire response
    var server_to_client: u8[..2048] = [];
    let consumed, ok = internal::handle_h2_server_ingress(
        sess, pipeline, timer, "127.0.0.1", client_to_server[..], 1000, server_to_client,
    );
    assert(ok);
    assert(consumed == client_to_server.len);

    // Verify Server emitted response:
    // Frame 1: Server SETTINGS (9-byte header + 24-byte payload = 33 bytes)
    assert(server_to_client.len >= 33);
    let s_hdr, err_s = internal::parse_frame_header(server_to_client[..9]);
    assert(err_s == rfc::H2_ERR_NO_ERROR);
    assert(s_hdr.frame_type == rfc::H2_FRAME_SETTINGS);
    assert(s_hdr.stream_id == 0);
    assert(s_hdr.length == 24);

    // Frame 2: Server SETTINGS ACK (9 bytes)
    assert(server_to_client.len >= 42);
    let ack_hdr, err_ack = internal::parse_frame_header(server_to_client[33..42]);
    assert(err_ack == rfc::H2_ERR_NO_ERROR);
    assert(ack_hdr.frame_type == rfc::H2_FRAME_SETTINGS);
    assert((ack_hdr.flags & rfc::H2_FLAG_ACK) != 0);
    assert(ack_hdr.stream_id == 0);

    // Frame 3: Response HEADERS for stream 1
    let resp_slice = server_to_client[42..];
    assert(resp_slice.len >= 9);
    let r_hdr, err_r = internal::parse_frame_header(resp_slice[..9]);
    assert(err_r == rfc::H2_ERR_NO_ERROR);
    assert(r_hdr.frame_type == rfc::H2_FRAME_HEADERS);
    assert(r_hdr.stream_id == 1);
    assert((r_hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0);

    // Decode response HPACK header block
    var dec_pseudo = internal::H2PseudoHeaders { .. };
    var dec_resp = wing::HeaderMap { .. };
    let hpack_payload = resp_slice[9..9 + r_hdr.length];
    let hpack_err = internal::decode_hpack_to_map(client_hpack, hpack_payload, dec_pseudo, dec_resp);
    assert(hpack_err == rfc::H2_ERR_NO_ERROR);
    assert(dec_pseudo.has_status && dec_pseudo.status == 200);
    print("H2_LOOPBACK: OK");
}

// 2. QUIC Wire Loopback:
// Client formats 1-RTT Short Header datagram with STREAM frame -> Server ingests, creates stream, updates flow control
fn test_quic_wire_loopback() {
    let scid: u8[4] = [0x50, 0x51, 0x52, 0x53];
    var server_conn = internal::new_quic_server_connection(scid[..]);
    server_conn.allow_unencrypted_test_packets = true;

    var dgram: u8[..256] = [];
    dgram.push(0x40); // 1-RTT Short Header
    dgram.append(scid[..]);
    dgram.push(0x01); // Packet number = 1

    internal::encode_max_data_frame(dgram, 800000);
    internal::encode_stream_frame(
        dgram, 0, 0, "PING_LOOPBACK", internal::QuicStreamFlags { fin: true, with_len: true },
    );

    var ack_out = internal::AckFrame { .. };
    let handled, needs_ack = internal::quic_conn_process_datagram(server_conn, dgram[..], 1000, ack_out);
    assert(handled);
    assert(needs_ack);

    let st_idx = internal::quic_table_find_stream(server_conn.stream_table, 0);
    assert(st_idx >= 0);
    assert(server_conn.flow_ctrl.max_data_remote == 800000);
    assert(server_conn.stream_table.streams[st_idx as i64].bytes_recv == 13);
    assert(server_conn.state == internal::QuicConnState.Established);

    print("QUIC_LOOPBACK: OK");
}

// 3. HTTP/3 Wire Loopback:
// Client formats Control Stream SETTINGS + Request Stream HEADERS with QPACK section -> Server parses and verifies
fn test_h3_wire_loopback() {
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };
    var server_conn = internal::new_h3_server_connection(settings);

    // 1. Control Stream (Stream ID 3, Unidirectional) with SETTINGS
    var ctrl_wire: u8[..128] = [];
    internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl_wire, settings);
    let err_ctrl = server_conn.handle_stream_data(3, false, ctrl_wire[..], false);
    assert(err_ctrl == rfc::H3_ERR_NO_ERROR);
    assert(server_conn.peer_settings_received);

    // 2. Request Stream (Stream ID 0, Bidirectional) with HEADERS frame
    // Encode with QPACK including a custom header (`x-loopback-id: 42`) and verify lossless HeaderMap extraction
    var cli_qpack = internal::new_qpack_table(0);
    var req_hdrs = wing::HeaderMap { .. };
    wing::append_header(req_hdrs, "x-loopback-id", "42");
    var req_pseudo = internal::H3PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/",
        ..
    };
    var req_wire:   u8[..256] = [];
    var qpack_inst: u8[..256] = [];
    assert(wire::encode_h3_headers_from_map(cli_qpack, 0, req_pseudo, req_hdrs, qpack_inst, req_wire));

    let err_req = server_conn.handle_stream_data(0, true, req_wire[..], false);
    assert(err_req == rfc::H3_ERR_NO_ERROR);

    let s_idx, found = internal::find_h3_stream_idx(server_conn, 0);
    assert(found);
    assert(server_conn.streams[s_idx].headers_received);
    assert(wing::get_header(server_conn.streams[s_idx].headers, "x-loopback-id") == "42");

    // 3. DATA frame with payload "HELLO_H3"
    let body = "HELLO_H3";
    var data_wire: u8[..64] = [];
    assert(internal::encode_h3_frame_header(data_wire, rfc::H3_FRAME_DATA, body.len as u64));
    data_wire.append(body);

    let err_data = server_conn.handle_stream_data(0, true, data_wire[..], true);
    assert(err_data == rfc::H3_ERR_NO_ERROR);
    assert(server_conn.streams[s_idx].received_body[..] == "HELLO_H3");
    assert(server_conn.streams[s_idx].fin_received);

    print("H3_LOOPBACK: OK");
}

fn run_10_verify_wire_loopback() {
    test_h2_wire_loopback();
    test_quic_wire_loopback();
    test_h3_wire_loopback();
}

// CHECK: H2_LOOPBACK: OK
// CHECK-NEXT: QUIC_LOOPBACK: OK
// CHECK-NEXT: H3_LOOPBACK: OK

// ============================================================================
// 11. verify_wire_rfc_seams_regress (11/12)
// ============================================================================
// CHECK: === [11/12] verify_wire_rfc_seams_regress ===

// Regression tests for cross-component seams and RFC edge cases in `wire` (F-WIRE-008..F-WIRE-013).

// F-WIRE-008: HPACK DynamicTable and QPACK QpackTable must roll back on partial encoding or frame buffer overflow.
fn test_f_wire_008_transactional_hpack_qpack_tables() {
    var dt = internal::new_dynamic_table(4096);
    var pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var hdrs = wing::HeaderMap { .. };
    wing::append_header(hdrs, "x-first-ok", " indexed-val-1");
    wing::append_header(hdrs, "x-second-long", "0123456789abcdef0123456789abcdef");

    // 1. encode_hpack_from_map fails on small buffer after inserting first header into `dt`
    var tiny_out: u8[..24] = [];
    var ok_h2_hdrs = wing::HeaderMap { .. };
    wing::append_header(ok_h2_hdrs, "x-first-ok", "indexed-val-1");
    wing::append_header(ok_h2_hdrs, "x-second-long", "0123456789abcdef0123456789abcdef");
    assert(!wire::encode_hpack_from_map(dt, pseudo, ok_h2_hdrs, tiny_out, false));
    assert(dt.count == 0 && dt.used_bytes == 0);

    // 2. encode_h2_headers_frame_from_map fails when output frame buffer cannot fit frame
    var tight_frame_out: u8[..16] = [];
    assert(!wire::encode_h2_headers_frame_from_map(dt, 1, pseudo, ok_h2_hdrs, true, tight_frame_out, 16384));
    assert(dt.count == 0 && dt.used_bytes == 0);

    // 3. encode_h3_headers_from_map fails when `out_frame` overflows after QPACK dynamic table insertion
    var qtbl = internal::new_qpack_table(4096);
    let _ = internal::qpack_set_capacity(qtbl, 4096);
    var qpseudo = internal::H3PseudoHeaders { has_status: true, status: 200, .. };
    var qenc:         u8[..256] = [];
    var tight_qframe: u8[..4]   = [];
    assert(!wire::encode_h3_headers_from_map(qtbl, 4, qpseudo, ok_h2_hdrs, qenc, tight_qframe));
    assert(qtbl.insert_count == 0 && qtbl.entries.len == 0 && qtbl.unacked_sections.len == 0);
    assert(qenc.len == 0 && tight_qframe.len == 0);

    print("F_WIRE_008_TRANSACTIONAL_TABLES: OK\n");
}

// F-WIRE-009: QPACK sensitive header protection, Connection-nominated header filtering, TE normalization, and RFC 9113/9114 bounds.
fn test_f_wire_009_qpack_sensitive_and_rfc_headers() {
    var qtbl_enc = internal::new_qpack_table(4096);
    let _ = internal::qpack_set_capacity(qtbl_enc, 4096);
    var qtbl_dec = internal::new_qpack_table(4096);
    let _ = internal::qpack_set_capacity(qtbl_dec, 4096);

    var req_hdrs = wing::HeaderMap { .. };
    wing::append_header(req_hdrs, "Authorization", "Bearer secret-jwt");
    wing::set_header(req_hdrs, "X-Api-Secret", "top-secret-key", true);
    wing::append_header(req_hdrs, "Connection", "x-internal-hop, keep-alive");
    wing::append_header(req_hdrs, "X-Internal-Hop", "must-be-stripped");
    wing::append_header(req_hdrs, "TE", "TRAILERS");

    var req_pseudo = internal::H3PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/secure",
        ..
    };
    var q_inst:  u8[..256] = [];
    var q_frame: u8[..512] = [];
    assert(wire::encode_h3_headers_from_map(qtbl_enc, 0, req_pseudo, req_hdrs, q_inst, q_frame));
    // Sensitive headers must NOT be inserted into QPACK dynamic table (`authorization` and `x-api-secret` stay literal with N=1)
    let _, auth_in_dyn, _ = internal::find_qpack_dynamic_field(qtbl_enc, "authorization", "Bearer secret-jwt");
    let _, sec_in_dyn, _ = internal::find_qpack_dynamic_field(qtbl_enc, "x-api-secret", "top-secret-key");
    assert(!auth_in_dyn && !sec_in_dyn);

    var q_off: u64 = 0;
    while q_off < (q_inst.len as u64) {
        let next_off, q_ie = internal::qpack_process_encoder_instruction(qtbl_dec, q_inst[..], q_off);
        assert(q_ie == internal::QpackError.None && next_off > q_off);
        q_off = next_off;
    }
    var dec_qpseudo = internal::H3PseudoHeaders { .. };
    var dec_qmap = wing::HeaderMap { .. };
    let q_err = wire::decode_h3_headers_to_map(qtbl_dec, 0, q_frame[2..], dec_qpseudo, dec_qmap);
    assert(q_err == internal::QpackError.None);
    assert(!wing::has_header(dec_qmap, "x-internal-hop"));
    assert(wing::get_header(dec_qmap, "te") == "trailers");
    // Custom sensitive header must preserve HEADER_FLAG_SENSITIVE across QPACK N-bit round-trip
    var found_sens = false;
    for &e in dec_qmap.entries {
        if wing::entry_name(dec_qmap, e) == "x-api-secret" {
            found_sens = wing::is_sensitive(e);
        }
    }
    assert(found_sens);

    // Verify HPACK also strips Connection-nominated tokens, normalizes `TE: TRAILERS` -> `trailers`, and rejects 101 / invalid pseudo
    var h2_dt_enc = internal::new_dynamic_table(4096);
    var h2_dt_dec = internal::new_dynamic_table(4096);
    var h2_req_pseudo = internal::H2PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/secure",
        ..
    };
    var h2_buf: u8[..512] = [];
    assert(wire::encode_hpack_from_map(h2_dt_enc, h2_req_pseudo, req_hdrs, h2_buf, false));
    var dec_h2_pseudo = internal::H2PseudoHeaders { .. };
    var dec_h2_map = wing::HeaderMap { .. };
    assert(wire::decode_hpack_to_map(h2_dt_dec, h2_buf[..], dec_h2_pseudo, dec_h2_map) == rfc::H2_ERR_NO_ERROR);
    assert(!wing::has_header(dec_h2_map, "x-internal-hop"));
    assert(wing::get_header(dec_h2_map, "te") == "trailers");

    // Status 101 (Switching Protocols) must be rejected by both H2 and H3 encoders (RFC 9113 §8.3.2, RFC 9114 §4.3.2)
    let empty_map = wing::HeaderMap { .. };
    let st101_h2 = internal::H2PseudoHeaders { has_status: true, status: 101, .. };
    let st101_h3 = internal::H3PseudoHeaders { has_status: true, status: 101, .. };
    h2_buf.clear();
    q_inst.clear();
    q_frame.clear();
    assert(!wire::encode_hpack_from_map(h2_dt_enc, st101_h2, empty_map, h2_buf, false));
    assert(!wire::encode_h3_headers_from_map(qtbl_enc, 0, st101_h3, empty_map, q_inst, q_frame));

    // Empty non-trailer pseudo-headers or mixed status+method must be rejected
    let empty_h2_pseudo = internal::H2PseudoHeaders { .. };
    let empty_h3_pseudo = internal::H3PseudoHeaders { .. };
    assert(!wire::encode_hpack_from_map(h2_dt_enc, empty_h2_pseudo, empty_map, h2_buf, false));
    assert(!wire::encode_h3_headers_from_map(qtbl_enc, 0, empty_h3_pseudo, empty_map, q_inst, q_frame));

    // decode_h3_headers_to_map must reject incomplete pseudo-headers (e.g. GET without :scheme/:path)
    let incomplete_qpack: u8[3] = [0x00, 0x00, 0xD1]; // :method = GET only
    assert(wire::decode_h3_headers_to_map(qtbl_dec, 0, incomplete_qpack[..], dec_qpseudo, dec_qmap) == internal::QpackError.MessageError);

    print("F_WIRE_009_QPACK_SENSITIVE_AND_RFC: OK\n");
}

// F-WIRE-010: HTTP/1.1 decode_h1_response_head HeaderMap status/version sync & smuggling rejection.
fn test_f_wire_010_h1_head_sync_and_smuggling() {
    var status: u16 = 0;
    var hdrs = wing::HeaderMap { .. };
    let consumed, err = wire::decode_h1_response_head("HTTP/1.0 404 Not Found\r\nServer: wing\r\n\r\n", status, hdrs);
    assert(err == wing::HeaderParseError.None && consumed > 0 && status == 404);
    assert(hdrs.status_code == 404 && hdrs.http_major == 1 && hdrs.http_minor == 0);

    // On header parse error after status line, `status` must reset to 0
    let _, bad_hdr_err = wire::decode_h1_response_head(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", status, hdrs,
    );
    assert(bad_hdr_err != wing::HeaderParseError.None && status == 0);

    // encode_h1_request / encode_h1_response must reject CL + TE smuggling and conflicting Content-Length
    var smuggle_hdrs = wing::HeaderMap { .. };
    wing::append_header(smuggle_hdrs, "Content-Length", "5");
    wing::append_header(smuggle_hdrs, "Transfer-Encoding", "chunked");
    var h1_out: u8[..256] = [];
    assert(!wire::encode_h1_request("POST", "/upload", "example.com", smuggle_hdrs, "hello", wire::H1HeaderFilterMode.PreserveAll, h1_out));
    assert(!wire::encode_h1_response(200, "OK", "wing", smuggle_hdrs, "hello", false, h1_out));

    var mismatch_cl = wing::HeaderMap { .. };
    wing::append_header(mismatch_cl, "Content-Length", "99");
    assert(!wire::encode_h1_request("POST", "/upload", "example.com", mismatch_cl, "hello", wire::H1HeaderFilterMode.PreserveAll, h1_out));
    assert(!wire::encode_h1_response(200, "OK", "wing", mismatch_cl, "hello", false, h1_out));

    print("F_WIRE_010_H1_SYNC_AND_SMUGGLING: OK\n");
}

// F-WIRE-011: decode_h2_frame_header stream association/length rules and encode_settings_frame RFC 9113 §6.5.2 bounds.
fn test_f_wire_011_h2_frame_and_settings_validation() {
    // PING frame on stream 1 (forbidden by RFC 9113 §6.7) must be rejected by decode_h2_frame_header
    let ping_sid1: u8[9] = [0x00, 0x00, 0x08, rfc::H2_FRAME_PING, 0x00, 0x00, 0x00, 0x00, 0x01];
    let _, err_ping_sid = wire::decode_h2_frame_header(ping_sid1[..]);
    assert(err_ping_sid == rfc::H2_ERR_PROTOCOL_ERROR);

    // PING frame with length 4 (instead of 8) must fail with FRAME_SIZE_ERROR
    let ping_len4: u8[9] = [0x00, 0x00, 0x04, rfc::H2_FRAME_PING, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, err_ping_len = wire::decode_h2_frame_header(ping_len4[..]);
    assert(err_ping_len == rfc::H2_ERR_FRAME_SIZE_ERROR);

    // encode_settings_frame must reject out-of-range MAX_FRAME_SIZE (< 16384) or ENABLE_PUSH > 1 (RFC 9113 §6.5.2)
    var s_out: u8[..64] = [];
    let bad_mfs: wire::WireSetting[1] = [wire::h2_setting(rfc::H2_SETTING_MAX_FRAME_SIZE, 1024)];
    assert(!wire::encode_settings_frame(bad_mfs[..], s_out));
    let bad_push: wire::WireSetting[1] = [wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 2)];
    assert(!wire::encode_settings_frame(bad_push[..], s_out));

    print("F_WIRE_011_H2_FRAME_AND_SETTINGS: OK\n");
}

// F-WIRE-012: reset_command_pool(pool, 0) reuse, out-of-order slot release, stale cmd rejection, and RecordingHeaders error state.
fn test_f_wire_012_pool_and_cmd_fsm() {
    let inst = wire::WireInstance { .. };
    var phys: wire::WirePhysicalDevice[..4] = [];
    let _ = wire::enumerate_physical_devices(inst, phys);
    let dev_info = wire::WireDeviceCreateInfo { .. };
    let pool_info = wire::WireCommandPoolCreateInfo { .. };
    var dev, _ = wire::create_wire_device(phys[0], dev_info);
    var pool, _ = wire::create_command_pool(dev, pool_info);

    // Allocate all 4 command buffers, then reset pool with flags = 0 (without RELEASE_RESOURCES_BIT)
    var c1, r1 = wire::allocate_command_buffer(pool);
    var c2, r2 = wire::allocate_command_buffer(pool);
    var c3, r3 = wire::allocate_command_buffer(pool);
    var c4, r4 = wire::allocate_command_buffer(pool);
    assert(wire::is_success(r1) && wire::is_success(r2) && wire::is_success(r3) && wire::is_success(r4));
    assert(wire::is_success(wire::reset_command_pool(pool, 0)));

    // Allocating after reset_command_pool(pool, 0) must succeed, and stale `c1` must not commit over `c5`
    var c5, r5 = wire::allocate_command_buffer(pool);
    assert(wire::is_success(r5));
    let begin_info = wire::WireCommandBufferBeginInfo { .. };
    let _ = wire::begin_command_buffer(c1, begin_info);
    let _ = wire::write_h2_preface(c1);
    let _ = wire::end_command_buffer(c1);
    let _, stale_commit_ok = wire::commit_command_buffer_to_arena(pool, c1);
    assert(!stale_commit_ok);

    // Failed HPACK command inside RecordingHeaders must allow end_command_buffer to return ErrorCommandBufferLocked
    let _ = wire::begin_command_buffer(c5, begin_info);
    assert(wire::begin_h2_headers(c5, 1, rfc::H2_FLAG_END_HEADERS));
    assert(!wire::hpack_indexed(c5, 0));
    let end_err = wire::end_command_buffer(c5);
    assert(end_err == wire::WireResult.ErrorCommandBufferLocked && c5.state == wire::WireCommandBufferState.Invalid);

    print("F_WIRE_012_POOL_AND_CMD_FSM: OK\n");
}

// F-WIRE-013: submit_to_cork consumed-buffer reset, Timeline semaphore monotonicity, and idempotent add_*_stage.
fn test_f_wire_013_cork_sync_and_pipeline() {
    let inst = wire::WireInstance { .. };
    var phys: wire::WirePhysicalDevice[..4] = [];
    let _ = wire::enumerate_physical_devices(inst, phys);
    let dev_info = wire::WireDeviceCreateInfo { .. };
    var dev, _ = wire::create_wire_device(phys[0], dev_info);

    // Timeline semaphore must reject non-monotonic backward values
    let sem_info = wire::WireSemaphoreCreateInfo {
        semaphore_type: wire::WireSemaphoreType.Timeline,
        initial_value:  20,
    };
    var sem, _ = wire::create_wire_semaphore(dev, sem_info);
    assert(!wire::is_success(wire::signal_wire_semaphore(sem, 10)));
    assert(sem.value == 20);

    // add_ingress_stage / add_egress_stage must not append duplicate stage IDs
    var pipe = wire::default_server_pipeline();
    let initial_in_len = pipe.ingress_stages.len;
    assert(wire::add_ingress_stage(pipe, wire::STAGE_ID_SRV_IN_AUTH_JWT));
    assert(pipe.ingress_stages.len == initial_in_len);

    print("F_WIRE_013_CORK_SYNC_AND_PIPELINE: OK\n");
}

fn run_11_verify_wire_rfc_seams_regress() {
    // CHECK: F_WIRE_008_TRANSACTIONAL_TABLES: OK
    // CHECK: F_WIRE_009_QPACK_SENSITIVE_AND_RFC: OK
    // CHECK: F_WIRE_010_H1_SYNC_AND_SMUGGLING: OK
    // CHECK: F_WIRE_011_H2_FRAME_AND_SETTINGS: OK
    // CHECK: F_WIRE_012_POOL_AND_CMD_FSM: OK
    // CHECK: F_WIRE_013_CORK_SYNC_AND_PIPELINE: OK
    test_f_wire_008_transactional_hpack_qpack_tables();
    test_f_wire_009_qpack_sensitive_and_rfc_headers();
    test_f_wire_010_h1_head_sync_and_smuggling();
    test_f_wire_011_h2_frame_and_settings_validation();
    test_f_wire_012_pool_and_cmd_fsm();
    test_f_wire_013_cork_sync_and_pipeline();
}

// ============================================================================
// 12. verify_wire_vulkan_conformance (12/12)
// ============================================================================
// CHECK: === [12/12] verify_wire_vulkan_conformance ===

// Verification of the full 7-tier Vulkan-similarity API pipeline in wire subsystem.

fn test_vulkan_wire_conformance() {
    print("=== VULKAN_WIRE_CONFORMANCE_SUITE ===\n");

    // Tier 1: Instance & Physical Device Enumeration
    let inst = wire::WireInstance { .. };
    assert(inst.api_version == 0x00400000);
    print("VULKAN_INSTANCE: OK\n");

    var phys_devs: wire::WirePhysicalDevice[..4] = [];
    let enum_res = wire::enumerate_physical_devices(inst, phys_devs);
    assert(wire::is_success(enum_res));
    assert(phys_devs.len >= 1);
    let phys = phys_devs[0];
    assert(phys.properties.max_buffer_capacity == 16384);
    print("PHYSICAL_DEVICE_ENUM: OK\n");

    // Tier 2: Logical Device Creation
    let dev_info = wire::WireDeviceCreateInfo {
        config: wire::WireDeviceConfig { .. },
        enabled_features: wire::WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     false,
            hardware_tls:      false,
            raw_frames:        true,
        },
    };
    var dev, create_dev_res = wire::create_wire_device(phys, dev_info);
    assert(wire::is_success(create_dev_res) && dev.is_active);
    print("LOGICAL_DEVICE_CREATED: OK\n");

    // Tier 3: Command Pool Memory Allocator
    let pool_info = wire::WireCommandPoolCreateInfo {
        flags:              wire::WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        queue_family_index: 0,
    };
    var pool, pool_res = wire::create_command_pool(dev, pool_info);
    assert(wire::is_success(pool_res) && pool.is_valid);

    let reset_pool_res = wire::reset_command_pool(pool, wire::WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT);
    assert(wire::is_success(reset_pool_res));
    print("COMMAND_POOL_RECYCLED: OK\n");

    // Tier 4: Pipeline State Object (PSO)
    let pipe_info = wire::WirePipelineCreateInfo {
        bind_point: wire::WirePipelineBindPoint.Transmit,
        layout: wire::WirePipelineLayout {
            max_frame_size: 16384,
            push_constants: [],
        },
        flags: 0,
    };
    var pipe, pipe_res = wire::create_wire_pipeline(dev, pipe_info);
    assert(wire::is_success(pipe_res) && pipe.is_valid);

    // Tier 5: Command Buffer Lifecycle FSM & Frame Recording
    var cmd, alloc_res = wire::allocate_command_buffer(pool);
    assert(wire::is_success(alloc_res) && cmd.state == wire::WireCommandBufferState.Initial);

    // Attempting to record before begin_command_buffer MUST fail
    let premature_rec = wire::write_h2_preface(cmd);
    assert(!premature_rec && cmd.has_error);

    // Begin recording
    let begin_info = wire::WireCommandBufferBeginInfo {
        flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    let begin_res = wire::begin_command_buffer(cmd, begin_info);
    assert(wire::is_success(begin_res) && cmd.state == wire::WireCommandBufferState.Recording);

    // Bind Pipeline State Object
    let bind_res = wire::cmd_bind_pipeline(cmd, wire::WirePipelineBindPoint.Transmit, pipe);
    assert(wire::is_success(bind_res));
    print("PIPELINE_STATE_BOUND: OK\n");

    // Command 1: Preface
    assert(wire::write_h2_preface(cmd));

    // Command 2: SETTINGS
    let s_list: wire::WireSetting[2] = [
        wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 65535),
    ];
    assert(wire::write_h2_settings(cmd, s_list[..]));

    // Command 3: Dynamic HEADERS Block with Interleave Protection
    assert(wire::begin_h2_headers(cmd, 1, rfc::H2_FLAG_END_HEADERS));
    assert(cmd.state == wire::WireCommandBufferState.RecordingHeaders);

    // Interleave rejection: writing frame while in RecordingHeaders must fail
    var interleave_cmd, i_res = wire::allocate_command_buffer(pool);
    assert(wire::is_success(i_res));
    wire::begin_command_buffer(interleave_cmd, begin_info);
    assert(wire::begin_h2_headers(interleave_cmd, 1, rfc::H2_FLAG_END_HEADERS));
    let ping_data: u8[8] = [0; 8];
    assert(!wire::write_h2_ping(interleave_cmd, ping_data, false));
    assert(interleave_cmd.has_error);
    wire::free_command_buffer(pool, interleave_cmd);

    //Valid HPACK entries on clean cmd (zero-staging in-place 9-byte frame header reservation)
    let hdr_start = cmd.headers_frame_offset;
    assert(hdr_start > 0);
    assert(wire::hpack_indexed(cmd, 2));
    assert(wire::hpack_indexed(cmd, 7));
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/vulkan-wire"));
    assert(wire::end_h2_headers(cmd));
    assert(cmd.state == wire::WireCommandBufferState.Recording);

    // Command 4: DATA Frame
    assert(wire::write_h2_data(cmd, 1, "test-stream-body", true));

    // End command buffer recording and commit to pool arena via core::ct_copy_bytes
    let end_res = wire::end_command_buffer(cmd);
    assert(wire::is_success(end_res) && cmd.state == wire::WireCommandBufferState.Executable);
    let arena_slice, commit_ok = wire::commit_command_buffer_to_arena(pool, cmd);
    assert(commit_ok && arena_slice.len == cmd.buf.len);
    print("COMMAND_BUFFER_LIFECYCLE_FSM: OK\n");

    // Verify wire::hpack_decode_string Huffman decoding (RFC 7541 Appendix C.4.1 "www.example.com")
    let huff_wire: u8[13] = [0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff];
    var huff_pos:     u64      = 0;
    var decoded_huff: u8[..64] = [];
    let huff_ok = wire::hpack_decode_string(huff_wire[..], huff_pos, decoded_huff);
    assert(huff_ok && huff_pos == 13);
    assert(core::ct_eq_bytes(decoded_huff[..], "www.example.com"));

    // Verify rfc::status_phrase, rfc::status_line_h1, rfc::is_empty_body_status, rfc::is_redirect_status
    assert(core::ct_eq_bytes(rfc::status_phrase(rfc::STATUS_OK), "OK"));
    assert(core::ct_eq_bytes(rfc::status_line_h1(rfc::STATUS_NOT_FOUND), "HTTP/1.1 404 Not Found\r\n"));
    assert(rfc::is_empty_body_status(rfc::STATUS_NO_CONTENT));
    assert(!rfc::is_empty_body_status(rfc::STATUS_OK));
    assert(rfc::is_redirect_status(rfc::STATUS_MOVED_PERMANENTLY));
    assert(!rfc::is_redirect_status(rfc::STATUS_OK));
    print("RFC_HELPERS_AND_HUFFMAN: OK\n");

    // Tier 6: Queue Acquisition, Batch Submission & Synchronization2
    var queue = wire::get_device_queue(dev, 0, 0);
    queue.driver = wire::WireDriverKind.Mock;
    queue.is_connected = true;

    // Verify WireQueue submit_to_cork and submit_to_transport over ring buffers
    var cork = core::CorkBuffer { .. };
    let cork_ok = wire::submit_to_cork(cmd, cork);
    assert(cork_ok && core::cork_pending(cork) == cmd.buf.len);
    print("WIRE_QUEUE_TLS13: OK\n");

    // Create Synchronization2 Fence and Semaphore
    let fence_info = wire::WireFenceCreateInfo { flags: 0 };
    var fence, f_res = wire::create_wire_fence(dev, fence_info);
    assert(wire::is_success(f_res) && fence.status == wire::WireFenceStatus.Unsignaled);

    let sem_info = wire::WireSemaphoreCreateInfo {
        semaphore_type: wire::WireSemaphoreType.Timeline,
        initial_value:  10,
    };
    var sem, sem_res = wire::create_wire_semaphore(dev, sem_info);
    assert(wire::is_success(sem_res) && sem.value == 10);
    print("SEMAPHORE_TIMELINE: OK\n");

    // Batch Submission
    let batch: wire::WireCommandBuffer[1] = [cmd];
    let submit_info = wire::WireSubmitInfo {
        stage_mask:       wire::WIRE_PIPELINE_STAGE_ALL_COMMANDS,
        wait_semaphore:   10,
        signal_semaphore: 20,
        bytes_submitted:  0,
    };

    let sent_bytes, sub_res = wire::queue_submit_batch(queue, batch[..], submit_info, fence);
    assert(wire::is_success(sub_res) && sent_bytes > 0);
    assert(fence.status == wire::WireFenceStatus.Signaled);
    print("FENCE_SIGNALED: OK\n");

    // Tier 7: Queue Shutdown and Descriptor Reset Invariant
    wire::close_wire_queue(queue);
    assert(queue.fd == -1);
    assert(!queue.is_connected);
    print("SOCKET_FD_INVARIANT: OK\n");

    // Resource Cleanup
    wire::free_command_buffer(pool, cmd);
    wire::destroy_command_pool(pool);
    wire::destroy_wire_pipeline(pipe);
    wire::destroy_wire_fence(fence);
    wire::destroy_wire_semaphore(sem);
    wire::destroy_wire_device(dev);
}

struct CustomAuditStage {
    pre_route_hits: i32 = 0,
    post_auth_hits: i32 = 0,
}

fn wing::on_server_stage(
    stage: CustomAuditStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    _req:  const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    _res:  wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PreRoute {
        stage.pre_route_hits += 1;
    } else if phase == wire::ServerHookPhase.PostAuth {
        stage.post_auth_hits += 1;
    }
    return wire::StageVerdict.Continue;
}

struct CustomHeaderStage {
    egress_hits: i32 = 0,
}

fn wing::on_server_stage(
    stage: CustomHeaderStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    _req:  const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PreSerialize {
        stage.egress_hits += 1;
        wing::set_header(res, "X-Custom-Stage", "active");
    }
    return wire::StageVerdict.Continue;
}

fn test_tier1_and_tier2_pipeline_conformance() {
    // 1. Tier 1 HTTP/1.1 codec round-trip into HeaderMap
    var req_hdrs = wing::HeaderMap { .. };
    wing::append_header(req_hdrs, "X-Trace", "t1");
    var h1_req_wire: u8[..512] = [];
    assert(wire::encode_h1_request(
        "GET", "/v1/items", "api.example.com", req_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, h1_req_wire,
    ));
    var parsed_req = wing::Request { .. };
    let ok_req_parse, _ = wing::parse_http1_wire_request(h1_req_wire[..], parsed_req);
    assert(ok_req_parse);
    assert(wing::header(parsed_req, "Host") == "api.example.com");
    assert(wing::header(parsed_req, "X-Trace") == "t1");

    var resp_hdrs = wing::HeaderMap { .. };
    wing::append_header(resp_hdrs, "Content-Type", "application/json");
    var h1_resp_wire: u8[..512] = [];
    assert(wire::encode_h1_response(200, "OK", "goose-wing", resp_hdrs, "{\"ok\":true}", false, h1_resp_wire));
    var parsed_resp_hdrs = wing::HeaderMap { .. };
    var parsed_status: u16 = 0;
    let resp_consumed, resp_err = wire::decode_h1_response_head(h1_resp_wire[..], parsed_status, parsed_resp_hdrs);
    assert(resp_err == wing::HeaderParseError.None && resp_consumed > 0 && parsed_status == 200);
    assert(wing::get_header(parsed_resp_hdrs, "Content-Type") == "application/json");
    print("TIER1_H1_CODEC: OK\n");

    // 2. Tier 1 HPACK & QPACK decode directly into HeaderMap
    var dt = internal::new_dynamic_table(4096);
    var hpack_buf: u8[..256] = [];
    var enc_pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var h2_in_map = wing::HeaderMap { .. };
    wing::append_header(h2_in_map, "x-h2-header", "val2");
    assert(wire::encode_hpack_from_map(dt, enc_pseudo, h2_in_map, hpack_buf, false));
    var h2_dec_dt = internal::new_dynamic_table(4096);
    var h2_pseudo = internal::H2PseudoHeaders { .. };
    var h2_map = wing::HeaderMap { .. };
    let h2_err = wire::decode_hpack_to_map(h2_dec_dt, hpack_buf[..], h2_pseudo, h2_map);
    assert(h2_err == rfc::H2_ERR_NO_ERROR && h2_pseudo.status == 200);
    assert(wing::get_header(h2_map, "x-h2-header") == "val2");

    var qpack_enc = internal::new_qpack_table(0);
    var qpack_dec = internal::new_qpack_table(0);
    var q_req_in = wing::HeaderMap { .. };
    wing::append_header(q_req_in, "x-h3-custom", "val3");
    var q_in_pseudo = internal::H3PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/h3",
        ..
    };
    var q_frame: u8[..256] = [];
    var q_inst:  u8[..256] = [];
    assert(wire::encode_h3_headers_from_map(qpack_enc, 0, q_in_pseudo, q_req_in, q_inst, q_frame));
    // Strip 2-byte H3 HEADERS frame header (type=0x01, len)
    let q_payload = q_frame[2..];
    var q_pseudo = internal::H3PseudoHeaders { .. };
    var q_map = wing::HeaderMap { .. };
    let q_err = wire::decode_h3_headers_to_map(qpack_dec, 0, q_payload, q_pseudo, q_map);
    assert(q_err == internal::QpackError.None && q_pseudo.path[..] == "/h3");
    assert(wing::get_header(q_map, "x-h3-custom") == "val3");

    // Verify WireCommandBuffer multi-protocol recording and H2 frame header decode
    var multi_cmd = wire::new_command_buffer();
    let begin_multi = wire::WireCommandBufferBeginInfo { flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT };
    assert(wire::cmd_encode_h1_request(multi_cmd, "GET", "/ping", "example.com", req_hdrs, ""));
    multi_cmd.reset();
    assert(wire::is_success(wire::begin_command_buffer(multi_cmd, begin_multi)));
    assert(wire::cmd_encode_h1_response(multi_cmd, 200, "OK", "wing", resp_hdrs, "ok", false));
    multi_cmd.reset();
    assert(wire::is_success(wire::begin_command_buffer(multi_cmd, begin_multi)));
    assert(wire::cmd_encode_h2_headers_map(multi_cmd, dt, 1, enc_pseudo, h2_in_map, true));
    let dec_hdr, dec_hdr_err = wire::decode_h2_frame_header(multi_cmd.buf[..]);
    assert(dec_hdr_err == rfc::H2_ERR_NO_ERROR && dec_hdr.stream_id == 1);
    multi_cmd.reset();
    assert(wire::is_success(wire::begin_command_buffer(multi_cmd, begin_multi)));
    assert(wire::cmd_encode_h3_headers_map(multi_cmd, qpack_enc, 0, q_in_pseudo, q_req_in, q_inst));
    assert(multi_cmd.buf.len > 0);
    print("TIER1_HPACK_QPACK_MAP: OK\n");

    // 3. Tier 2 PipelineState step combinator + Server Stage Bricks + <UserStage> hook
    var pstate = wire::begin_pipeline();
    assert(wire::can_continue(pstate));
    assert(wire::step(pstate, wire::StageVerdict.Continue));
    assert(!wire::step(pstate, wire::StageVerdict.ShortCircuit { status_code: 204 }));
    assert(!wire::can_continue(pstate));

    var srv_cfg = wing::new_default_server_pipeline_config("example.com");
    wire::disable_ingress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_SLOWLORIS);
    wire::enable_ingress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_SLOWLORIS);
    wire::disable_egress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_OUT_METRICS);
    wire::enable_egress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_OUT_METRICS);
    let full_pso = wing::DEFAULT_ROUTE_PSO_MASK | wing::STAGE_EGRESS_ETAG | wing::STAGE_EGRESS_COMPRESS_GZIP | wing::STAGE_EGRESS_METRICS;
    assert(wing::add_route_pso(srv_cfg.router, "GET", "/custom", 1002, full_pso));
    assert(wire::add_ingress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_AUTH_JWT));
    assert(wire::add_egress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_OUT_ETAG));

    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var sreq = wing::new_request("GET", "/custom");
    wing::set_header(sreq, "Host", "example.com");
    wing::set_header(sreq, "Sec-Fetch-Site", "same-origin");
    wing::set_header(sreq, "Accept-Encoding", "gzip");
    var sres = wing::Response { .. };
    var sfut = internal::new_inline_handler_future(0);
    var custom_chain = wire::chain_stages(CustomAuditStage { .. }, CustomHeaderStage { .. });
    let sout = wing::execute_server_pipeline_with_stage(
        srv_cfg, timer, "127.0.0.1", sreq, 1005000000, sres, sfut, custom_chain,
    );
    assert(sout == wing::PipelineOutcome.Handled && sres.status_code == 200);
    assert(custom_chain.first.pre_route_hits == 1 && custom_chain.first.post_auth_hits == 1);
    assert(custom_chain.next.egress_hits == 1);
    assert(wing::header(sres, "X-Custom-Stage") == "active");
    assert(wing::header(sres, "Content-Encoding") == "gzip");
    assert(wing::has_header(sres, "ETag"));
    assert(wing::has_header(sres, "Server-Timing"));
    print("TIER2_STAGE_CONSTRUCTOR: OK\n");
}

fn run_12_verify_wire_vulkan_conformance() {
    // CHECK: === VULKAN_WIRE_CONFORMANCE_SUITE ===
    // CHECK: VULKAN_INSTANCE: OK
    // CHECK: PHYSICAL_DEVICE_ENUM: OK
    // CHECK: LOGICAL_DEVICE_CREATED: OK
    // CHECK: COMMAND_POOL_RECYCLED: OK
    // CHECK: PIPELINE_STATE_BOUND: OK
    // CHECK: COMMAND_BUFFER_LIFECYCLE_FSM: OK
    // CHECK: RFC_HELPERS_AND_HUFFMAN: OK
    // CHECK: WIRE_QUEUE_TLS13: OK
    // CHECK: SEMAPHORE_TIMELINE: OK
    // CHECK: FENCE_SIGNALED: OK
    // CHECK: SOCKET_FD_INVARIANT: OK
    // CHECK: TIER1_H1_CODEC: OK
    // CHECK: TIER1_HPACK_QPACK_MAP: OK
    // CHECK: TIER2_STAGE_CONSTRUCTOR: OK
    test_vulkan_wire_conformance();
    test_tier1_and_tier2_pipeline_conformance();
}

fn main() {
    print("\n=== [1/12] verify_cross_protocol_differential ===\n");
    run_01_verify_cross_protocol_differential();
    print("\n=== [2/12] verify_live_e2e_workflows ===\n");
    run_02_verify_live_e2e_workflows();
    print("\n=== [3/12] verify_module_seams_regress ===\n");
    run_03_verify_module_seams_regress();
    print("\n=== [4/12] verify_readme_quickstart ===\n");
    run_04_verify_readme_quickstart();
    print("\n=== [5/12] verify_wire_api ===\n");
    run_05_verify_wire_api();
    print("\n=== [6/12] verify_wire_benchmarks ===\n");
    run_06_verify_wire_benchmarks();
    print("\n=== [7/12] verify_wire_bounds ===\n");
    run_07_verify_wire_bounds();
    print("\n=== [8/12] verify_wire_framing ===\n");
    run_08_verify_wire_framing();
    print("\n=== [9/12] verify_wire_hierarchy ===\n");
    run_09_verify_wire_hierarchy();
    print("\n=== [10/12] verify_wire_loopback ===\n");
    run_10_verify_wire_loopback();
    print("\n=== [11/12] verify_wire_rfc_seams_regress ===\n");
    run_11_verify_wire_rfc_seams_regress();
    print("\n=== [12/12] verify_wire_vulkan_conformance ===\n");
    run_12_verify_wire_vulkan_conformance();
}
