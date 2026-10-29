// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

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
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

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
    let hdr, err = wing::parse_h2_frame_header(buf);
    if err != wing::H2ErrorCode.NoError {
        return 1;
    }
    if !hdr.valid {
        return 2;
    }
    return (hdr.stream_id & 0x7FFFFFFF);
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
    var framer = wing::H2SecurityFramer { .. };

    // 1. Initial HEADERS frame on stream 1 without END_HEADERS
    let h_hdr = wing::H2FrameHeader {
        payload_len: 128,
        frame_type: wing::H2FrameType.Headers,
        raw_type: 0x1,
        flags: 0x0,
        stream_id: 1,
        valid: true,
    };
    let err0 = wing::process_incoming_frame(framer, h_hdr);
    assert(err0 == wing::H2ErrorCode.NoError);
    assert(framer.state == wing::H2ConnState.ExpectContinuation);
    assert(framer.continuation_stream_id == 1);
    print("H2_EXPECT_CONTINUATION_STATE: OK");

    // 2. Interleaved PING frame on stream 0 -> ProtocolError
    let ping_hdr = wing::H2FrameHeader {
        payload_len: 8,
        frame_type: wing::H2FrameType.Ping,
        raw_type: 0x6,
        flags: 0x0,
        stream_id: 0,
        valid: true,
    };
    let err_ping = wing::process_incoming_frame(framer, ping_hdr);
    assert(err_ping == wing::H2ErrorCode.ProtocolError);
    assert(framer.state == wing::H2ConnState.Closed);
    print("H2_INTERLEAVED_PING_BAN: PROTOCOL_ERROR");

    // 3. Reset framer: Interleaved DATA frame on stream 1 -> ProtocolError
    var framer_data = wing::H2SecurityFramer { .. };
    wing::process_incoming_frame(framer_data, h_hdr);
    let data_hdr = wing::H2FrameHeader {
        payload_len: 64,
        frame_type: wing::H2FrameType.Data,
        raw_type: 0x0,
        flags: 0x0,
        stream_id: 1,
        valid: true,
    };
    let err_data = wing::process_incoming_frame(framer_data, data_hdr);
    assert(err_data == wing::H2ErrorCode.ProtocolError);
    assert(framer_data.state == wing::H2ConnState.Closed);
    print("H2_INTERLEAVED_DATA_BAN: PROTOCOL_ERROR");

    // 4. Reset framer: CONTINUATION on wrong stream ID (stream 3 instead of 1) -> ProtocolError
    var framer_mismatch = wing::H2SecurityFramer { .. };
    wing::process_incoming_frame(framer_mismatch, h_hdr);
    let cont_bad_sid = wing::H2FrameHeader {
        payload_len: 64,
        frame_type: wing::H2FrameType.Continuation,
        raw_type: 0x9,
        flags: 0x0,
        stream_id: 3,
        valid: true,
    };
    let err_bad_sid = wing::process_incoming_frame(framer_mismatch, cont_bad_sid);
    assert(err_bad_sid == wing::H2ErrorCode.ProtocolError);
    assert(framer_mismatch.state == wing::H2ConnState.Closed);
    print("H2_MISMATCHED_STREAM_BAN: PROTOCOL_ERROR");

    // 5. Unsolicited CONTINUATION frame when state is Idle -> ProtocolError
    var framer_idle = wing::H2SecurityFramer { .. };
    let cont_unsolicited = wing::H2FrameHeader {
        payload_len: 64,
        frame_type: wing::H2FrameType.Continuation,
        raw_type: 0x9,
        flags: wing::H2_FLAG_END_HEADERS,
        stream_id: 1,
        valid: true,
    };
    let err_unsolicited = wing::process_incoming_frame(framer_idle, cont_unsolicited);
    assert(err_unsolicited == wing::H2ErrorCode.ProtocolError);
    print("H2_UNSOLICITED_CONTINUATION_BAN: PROTOCOL_ERROR");

    // 6. CONTINUATION flood DoS (CVE-2024-27983): Send 5 allowed, 6th triggers EnhanceYourCalm
    var framer_flood = wing::H2SecurityFramer { .. };
    wing::process_incoming_frame(framer_flood, h_hdr);
    for _ in 5 {
        let cont_ok = wing::H2FrameHeader {
            payload_len: 10,
            frame_type: wing::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let st_ok = wing::process_incoming_frame(framer_flood, cont_ok);
        assert(st_ok == wing::H2ErrorCode.NoError);
    }
    let cont_6th = wing::H2FrameHeader {
        payload_len: 10,
        frame_type: wing::H2FrameType.Continuation,
        raw_type: 0x9,
        flags: 0x0,
        stream_id: 1,
        valid: true,
    };
    let err_flood = wing::process_incoming_frame(framer_flood, cont_6th);
    assert(err_flood == wing::H2ErrorCode.EnhanceYourCalm);
    assert(framer_flood.state == wing::H2ConnState.Closed);
    print("H2_CONTINUATION_FLOOD_LIMIT: ENHANCE_YOUR_CALM");

    // 7. Cumulative header block size DoS limit (> 8192 bytes)
    var framer_size = wing::H2SecurityFramer { .. };
    let big_h_hdr = wing::H2FrameHeader {
        payload_len: 8000,
        frame_type: wing::H2FrameType.Headers,
        raw_type: 0x1,
        flags: 0x0,
        stream_id: 1,
        valid: true,
    };
    wing::process_incoming_frame(framer_size, big_h_hdr);
    let big_cont_hdr = wing::H2FrameHeader {
        payload_len: 500,
        frame_type: wing::H2FrameType.Continuation,
        raw_type: 0x9,
        flags: 0x0,
        stream_id: 1,
        valid: true,
    };
    let err_size = wing::process_incoming_frame(framer_size, big_cont_hdr);
    assert(err_size == wing::H2ErrorCode.EnhanceYourCalm);
    assert(framer_size.state == wing::H2ConnState.Closed);
    print("H2_CUMULATIVE_BLOCK_SIZE_LIMIT: ENHANCE_YOUR_CALM");
}

fn test_h2_dos_and_stream_parity() {
    // 1. Rapid Reset DoS (CVE-2023-44487): 100 allowed, 101st triggers EnhanceYourCalm
    var framer_rr = wing::H2SecurityFramer { .. };
    for _ in 100 {
        let rst_hdr = wing::H2FrameHeader {
            payload_len: 4,
            frame_type: wing::H2FrameType.RstStream,
            raw_type: 0x3,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let st_rst = wing::process_incoming_frame(framer_rr, rst_hdr);
        assert(st_rst == wing::H2ErrorCode.NoError);
    }
    let rst_101 = wing::H2FrameHeader {
        payload_len: 4,
        frame_type: wing::H2FrameType.RstStream,
        raw_type: 0x3,
        flags: 0x0,
        stream_id: 1,
        valid: true,
    };
    let err_rr = wing::process_incoming_frame(framer_rr, rst_101);
    assert(err_rr == wing::H2ErrorCode.EnhanceYourCalm);
    assert(framer_rr.state == wing::H2ConnState.Closed);
    print("H2_RAPID_RESET_DEFENSE: ENHANCE_YOUR_CALM");

    // 2. Ping flood DoS: 10 allowed, 11th triggers EnhanceYourCalm
    var framer_ping = wing::H2SecurityFramer { .. };
    for _ in 10 {
        let ping_hdr = wing::H2FrameHeader {
            payload_len: 8,
            frame_type: wing::H2FrameType.Ping,
            raw_type: 0x6,
            flags: 0x0,
            stream_id: 0,
            valid: true,
        };
        let st_p = wing::process_incoming_frame(framer_ping, ping_hdr);
        assert(st_p == wing::H2ErrorCode.NoError);
    }
    let ping_11 = wing::H2FrameHeader {
        payload_len: 8,
        frame_type: wing::H2FrameType.Ping,
        raw_type: 0x6,
        flags: 0x0,
        stream_id: 0,
        valid: true,
    };
    let err_ping_flood = wing::process_incoming_frame(framer_ping, ping_11);
    assert(err_ping_flood == wing::H2ErrorCode.EnhanceYourCalm);
    print("H2_PING_FLOOD_DEFENSE: ENHANCE_YOUR_CALM");

    // 3. Client stream parity: Client HEADERS on even stream ID (stream 2) -> ProtocolError
    var framer_parity = wing::H2SecurityFramer { .. };
    let even_hdr = wing::H2FrameHeader {
        payload_len: 32,
        frame_type: wing::H2FrameType.Headers,
        raw_type: 0x1,
        flags: wing::H2_FLAG_END_HEADERS,
        stream_id: 2,
        valid: true,
    };
    let err_parity = wing::process_incoming_frame(framer_parity, even_hdr);
    assert(err_parity == wing::H2ErrorCode.ProtocolError);
    print("H2_EVEN_STREAM_ID_BAN: PROTOCOL_ERROR");
}

fn test_h2_pseudo_header_invariants() {
    // 1. Pseudo-header after regular header (RFC 9113 §8.3)
    var list1 = wing::DecodedH2HeaderList { .. };
    list1.has_regular_header = true;
    let err_order = wing::validate_header_ordering_and_rules(list1, ":method", "GET");
    assert(err_order == wing::ERR_PROTOCOL_ERROR);
    print("H2_PSEUDO_ORDERING_INVARIANT: PROTOCOL_ERROR");

    // 2. Duplicate pseudo-header
    var list2 = wing::DecodedH2HeaderList { .. };
    let _ = wing::validate_header_ordering_and_rules(list2, ":method", "GET");
    list2.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });
    let err_dup = wing::validate_header_ordering_and_rules(list2, ":method", "POST");
    assert(err_dup == wing::ERR_PROTOCOL_ERROR);
    print("H2_DUPLICATE_PSEUDO_BAN: PROTOCOL_ERROR");

    // 3. Undefined pseudo-header
    var list3 = wing::DecodedH2HeaderList { .. };
    let err_undef = wing::validate_header_ordering_and_rules(list3, ":custom", "val");
    assert(err_undef == wing::ERR_PROTOCOL_ERROR);
    print("H2_UNDEFINED_PSEUDO_BAN: PROTOCOL_ERROR");

    // 4. Forbidden connection-specific headers in HTTP/2 (RFC 9113 §8.2.2)
    var list4 = wing::DecodedH2HeaderList { .. };
    let err_conn = wing::validate_header_ordering_and_rules(list4, "connection", "close");
    assert(err_conn == wing::ERR_PROTOCOL_ERROR);
    let err_te = wing::validate_header_ordering_and_rules(list4, "transfer-encoding", "chunked");
    assert(err_te == wing::ERR_PROTOCOL_ERROR);
    let err_upg = wing::validate_header_ordering_and_rules(list4, "upgrade", "websocket");
    assert(err_upg == wing::ERR_PROTOCOL_ERROR);
    let err_ka = wing::validate_header_ordering_and_rules(list4, "keep-alive", "timeout=5");
    assert(err_ka == wing::ERR_PROTOCOL_ERROR);
    print("H2_FORBIDDEN_CONNECTION_HEADERS: PROTOCOL_ERROR");

    // 5. TE header with disallowed value
    var list5 = wing::DecodedH2HeaderList { .. };
    let err_te_val = wing::validate_header_ordering_and_rules(list5, "te", "gzip");
    assert(err_te_val == wing::ERR_PROTOCOL_ERROR);
    print("H2_DISALLOWED_TE_VALUE: PROTOCOL_ERROR");

    // 6. TE header with allowed 'trailers'
    var list6 = wing::DecodedH2HeaderList { .. };
    let ok_te_val = wing::validate_header_ordering_and_rules(list6, "te", "trailers");
    assert(ok_te_val == wing::ERR_NO_ERROR);
    print("H2_ALLOWED_TE_TRAILERS: OK");

    // 7. :authority forbidden characters (@ and /)
    var list7 = wing::DecodedH2HeaderList { .. };
    let err_auth_at = wing::validate_header_ordering_and_rules(list7, ":authority", "admin@example.com");
    assert(err_auth_at == wing::ERR_PROTOCOL_ERROR);
    let err_auth_slash = wing::validate_header_ordering_and_rules(list7, ":authority", "example.com/api");
    assert(err_auth_slash == wing::ERR_PROTOCOL_ERROR);
    print("H2_AUTHORITY_FORBIDDEN_CHARS: PROTOCOL_ERROR");

    // 8. :authority vs Host mismatch
    var list8 = wing::DecodedH2HeaderList { .. };
    let _ = wing::validate_header_ordering_and_rules(list8, ":authority", "example.com");
    list8.fields.push(wing::DecodedH2Header { name: ":authority", value: "example.com", .. });
    let err_mismatch = wing::validate_header_ordering_and_rules(list8, "host", "attacker.com");
    assert(err_mismatch == wing::ERR_PROTOCOL_ERROR);
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

fn main() {
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
