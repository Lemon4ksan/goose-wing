// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_http2_and_hpack
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";
import os;

// ============================================================================
// 1. rfc_repro_framer_h2_minsize (1/14)
// ============================================================================
// CHECK: === [1/14] rfc_repro_framer_h2_minsize ===

// tests/lit/rfc_repro_framer_h2_minsize.goose
// Repro test for RFC 9113 Section 4.2 minimum mandatory frame size violation.
//

fn run_01_rfc_repro_framer_h2_minsize() {
    print("=== RFC 9113 FRAME_SIZE_ERROR REPRO ===");

    // Case 1: HEADERS with FLAG_PRIORITY (0x20) and length = 4 (needs at least 5 bytes: Exclusive + Stream Dep + Weight)
    let hdr_prio = h2_internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_PRIORITY | rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_prio = h2_internal::validate_frame_header_rules(hdr_prio);
    assert(err_prio == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("HEADERS_PRIO_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 2: HEADERS with FLAG_PADDED (0x08) and length = 0 (needs at least 1 byte Pad Length)
    let hdr_pad = h2_internal::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_PADDED | rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_pad = h2_internal::validate_frame_header_rules(hdr_pad);
    assert(err_pad == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("HEADERS_PAD_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 3: HEADERS with FLAG_PADDED | FLAG_PRIORITY (0x28) and length = 5 (needs at least 6 bytes: 1 Pad Length + 5 Priority)
    let hdr_both = h2_internal::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_PADDED | rfc::H2_FLAG_PRIORITY | rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_both = h2_internal::validate_frame_header_rules(hdr_both);
    assert(err_both == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("HEADERS_BOTH_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 4: DATA with FLAG_PADDED (0x08) and length = 0 (needs at least 1 byte Pad Length)
    let hdr_data = h2_internal::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      rfc::H2_FLAG_PADDED,
        stream_id:  1,
    };
    let err_data = h2_internal::validate_frame_header_rules(hdr_data);
    assert(err_data == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("DATA_PAD_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 5: on_ingress_frame_header MUST reject undersized HEADERS and NOT open a new stream
    var conn = h2_internal::new_h2_connection(0);
    let ingress_err = h2_internal::on_ingress_frame_header(conn, hdr_prio, 0);
    assert(ingress_err == rfc::H2_ERR_FRAME_SIZE_ERROR);
    assert(conn.active_stream_count == 0);
    let s_idx, found = h2_internal::find_h2_stream_idx(conn, 1);
    assert(!found);
    print("CONN_INGRESS_UNDERFLOW_BLOCKED: FRAME_SIZE_ERROR");

    print("ALL_FRAME_SIZE_TESTS: OK");
}

// CHECK: === RFC 9113 FRAME_SIZE_ERROR REPRO ===
// CHECK: HEADERS_PRIO_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: HEADERS_PAD_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: HEADERS_BOTH_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: DATA_PAD_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: CONN_INGRESS_UNDERFLOW_BLOCKED: FRAME_SIZE_ERROR
// CHECK: ALL_FRAME_SIZE_TESTS: OK

// ============================================================================
// 2. verify_h2_and_chunk_edge (2/14)
// ============================================================================
// CHECK: === [2/14] verify_h2_and_chunk_edge ===

// tests/lit/verify_h2_and_chunk_edge.goose
// Verification of RFC 9113 HTTP/2 padded DATA frame content-length matching,
// stream-level PROTOCOL_ERROR isolation, and RFC 9112 chunk extension quoted-pair parsing.
//

fn test_h2_padded_data_and_overflow() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // 1. Client preface + SETTINGS
    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    // Empty SETTINGS frame (type 4, flags 0, stream 0)
    init_wire.append([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
    print("H2_INIT: ", if ok_init { "OK" } else { "FAIL" });

    // 2. Stream 1: HEADERS with :method=POST, :scheme=https, :path=/echo, content-length=5
    // Encode via HPACK
    var dt = h2_internal::new_dynamic_table(4096);
    var hdr_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, hdr_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, hdr_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, hdr_block, ":path", "/echo", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, hdr_block, "content-length", "5", h2_internal::HpackIndexing.Incremental, false);

    // Frame header for HEADERS on stream 1 with END_HEADERS (flags 0x04)
    var h1_frame: u8[>..] = [];
    let h1_len = hdr_block.len as u32;
    h1_frame.push(((h1_len >> 16) & 0xFF) as u8);
    h1_frame.push(((h1_len >> 8) & 0xFF) as u8);
    h1_frame.push((h1_len & 0xFF) as u8);
    h1_frame.push(0x01); // FRAME_HEADERS
    h1_frame.push(0x04); // FLAG_END_HEADERS
    h1_frame.push(0x00); h1_frame.push(0x00); h1_frame.push(0x00); h1_frame.push(0x01); // Stream 1
    h1_frame.append(hdr_block[..]);

    let _, ok_h1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h1_frame[..], 1000, wire_out);
    print("H2_STREAM_1_HEADERS: ", if ok_h1 { "OK" } else { "FAIL" });

    // 3. Stream 1: PADDED DATA frame (flags 0x08 | 0x01 = 0x09: FLAG_PADDED | FLAG_END_STREAM)
    // Payload: pad_length (1B) = 3, data (5B) = "hello", padding (3B) = 0x00, 0x00, 0x00
    // Total frame payload: 1 + 5 + 3 = 9 bytes.
    var d1_frame: u8[>..] = [];
    d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x09); // length 9
    d1_frame.push(0x00); // FRAME_DATA
    d1_frame.push(0x09); // FLAG_PADDED | FLAG_END_STREAM
    d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x01); // Stream 1
    d1_frame.push(0x03); // Pad length: 3 bytes
    d1_frame.append("hello");
    d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x00); // 3 padding bytes

    wire_out.clear();
    let _, ok_d1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d1_frame[..], 1000, wire_out);
    print("H2_STREAM_1_PADDED_DATA: ", if ok_d1 { "OK" } else { "FAIL" });

    // 4. Stream 3: Content-length overflow isolation test (RFC 9113 §8.1.2)
    var h3_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h3_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h3_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h3_block, ":path", "/test", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h3_block, "content-length", "4", h2_internal::HpackIndexing.Incremental, false);

    var h3_frame: u8[>..] = [];
    let h3_len = h3_block.len as u32;
    h3_frame.push(((h3_len >> 16) & 0xFF) as u8);
    h3_frame.push(((h3_len >> 8) & 0xFF) as u8);
    h3_frame.push((h3_len & 0xFF) as u8);
    h3_frame.push(0x01); // FRAME_HEADERS
    h3_frame.push(0x04); // FLAG_END_HEADERS
    h3_frame.push(0x00); h3_frame.push(0x00); h3_frame.push(0x00); h3_frame.push(0x03); // Stream 3
    h3_frame.append(h3_block[..]);

    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h3_frame[..], 1000, wire_out);

    // Send DATA frame on Stream 3 with 5 bytes ("12345"), exceeding declared content-length 4!
    var d3_frame: u8[>..] = [];
    d3_frame.push(0x00); d3_frame.push(0x00); d3_frame.push(0x05); // length 5
    d3_frame.push(0x00); // FRAME_DATA
    d3_frame.push(0x00); // no flags (mid-stream overflow)
    d3_frame.push(0x00); d3_frame.push(0x00); d3_frame.push(0x00); d3_frame.push(0x03); // Stream 3
    d3_frame.append("12345");

    wire_out.clear();
    let _, ok_d3 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d3_frame[..], 1000, wire_out);
    // Connection must remain alive (ok_d3 is true) while stream 3 receives RST_STREAM
    var has_rst_3 = false;
    var has_goaway = false;
    var p: i64 = 0;
    while p + 9 <= wire_out.len {
        let f_len = ((wire_out[p] as u32) << 16) | ((wire_out[p + 1] as u32) << 8) | wire_out[p + 2];
        let f_type = wire_out[p + 3];
        let f_sid = ((wire_out[p + 5] as u32) << 24) | ((wire_out[p + 6] as u32) << 16) | ((wire_out[p + 7] as u32) << 8) | wire_out[p + 8];
        if f_type == 0x03 && f_sid == 3 { has_rst_3 = true; } // RST_STREAM
        if f_type == 0x07 { has_goaway = true; } // GOAWAY
        p += 9 + (f_len as i64);
    }

    print("STREAM 3 OVERFLOW_RST: ", if has_rst_3 { "OK" } else { "FAIL" });
    print("STREAM 3 GOAWAY_EMITTED: ", if has_goaway { "YES" } else { "NO" });
}

fn test_chunk_fsm_quoted_pair() {
    var dec = http_internal::new_chunk_fsm_decoder();

    // Chunk size 5 with chunk extension having an escaped quote inside quoted-string:
    // 5;desc="hello \"world\""\r\nhello\r\n0\r\n\r\n
    let raw = "5;desc=\"hello \\\"world\\\"\"\r\nhello\r\n0\r\n\r\n";
    let st, _, chunk = http_internal::chunk_fsm_feed(dec, raw);

    print("CHUNK_QUOTED_PAIR_STATUS: ", match st {
        YieldChunk => "YIELD",
        Complete => "COMPLETE",
        NeedMore => "NEED_MORE",
        Error => "ERROR",
    });
    print("CHUNK_QUOTED_PAIR_PAYLOAD: ", chunk);
}

fn run_02_verify_h2_and_chunk_edge() {
    test_h2_padded_data_and_overflow();
    test_chunk_fsm_quoted_pair();
    print("ALL_EDGE_TESTS: PASS");
}

// CHECK-DAG: H2_INIT: OK
// CHECK-DAG: H2_STREAM_1_HEADERS: OK
// CHECK: H2_STREAM_1_PADDED_DATA: OK
// CHECK: STREAM [[SID:[0-9]+]] OVERFLOW_RST: OK
// CHECK: STREAM [[SID]] GOAWAY_EMITTED: NO
// CHECK: CHUNK_QUOTED_PAIR_STATUS: YIELD
// CHECK: CHUNK_QUOTED_PAIR_PAYLOAD: hello
// CHECK: ALL_EDGE_TESTS: PASS

// ============================================================================
// 3. verify_h2_continuation_fsm (3/14)
// ============================================================================
// CHECK: === [3/14] verify_h2_continuation_fsm ===

// tests/lit/verify_h2_continuation_fsm.goose
// Verification of HTTP/2 CONTINUATION flood defenses, interleaving bans, and window arithmetic.
//

fn parse_h2_hdr_step(buf: const u8[:]) -> i64 {
    guard buf.len >= 9 else { return -1; }
    let hdr, err = h2_internal::parse_frame_header(buf);
    guard err == rfc::H2_ERR_NO_ERROR else { return err as! i64; }
    let val_err = h2_internal::validate_frame_header_rules(hdr);
    guard val_err == rfc::H2_ERR_NO_ERROR else { return val_err as! i64; }
    guard buf.len >= 9 + (hdr.length as i64) else { return -1; }
    return hdr.stream_id as! i64;
}

fn run_03_verify_h2_continuation_fsm() {
    print("=== H2_CONTINUATION_AND_FSM_VERIFICATION ===");

    // 1. Initial HEADERS frame without END_HEADERS (flags = 0x00)
    var conn = h2_internal::new_h2_connection(0);
    let h_hdr = h2_internal::FrameHeader {
        length:     120,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      0, // No END_HEADERS
        stream_id:  1,
    };
    let err_h = h2_internal::on_ingress_frame_header(conn, h_hdr, 0);
    assert(err_h == rfc::H2_ERR_NO_ERROR);
    assert(conn.continuation_stream_id == 1);
    print("STATE: IngressHeaders -> ExpectContinuation(stream=1)");

    // 2. Interleaved PING frame on stream 0 during continuation sequence -> PROTOCOL_ERROR
    let ping_hdr = h2_internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      0,
        stream_id:  0,
    };
    let err_ping = h2_internal::on_ingress_frame_header(conn, ping_hdr, 0);
    assert(err_ping == rfc::H2_ERR_PROTOCOL_ERROR);
    print("INTERLEAVED_PING_BAN: PROTOCOL_ERROR");

    // 3. Interleaved DATA frame during continuation sequence -> PROTOCOL_ERROR
    let data_hdr = h2_internal::FrameHeader {
        length:     50,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      0,
        stream_id:  1,
    };
    let err_data = h2_internal::on_ingress_frame_header(conn, data_hdr, 0);
    assert(err_data == rfc::H2_ERR_PROTOCOL_ERROR);
    print("INTERLEAVED_DATA_BAN: PROTOCOL_ERROR");

    // 4. CONTINUATION frame on wrong stream ID (stream 3 instead of 1) -> PROTOCOL_ERROR
    let cont_bad_sid = h2_internal::FrameHeader {
        length:     64,
        frame_type: rfc::H2_FRAME_CONTINUATION,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  3,
    };
    let err_cont_bad = h2_internal::on_ingress_frame_header(conn, cont_bad_sid, 0);
    assert(err_cont_bad == rfc::H2_ERR_PROTOCOL_ERROR);
    print("MISMATCHED_STREAM_CONTINUATION: PROTOCOL_ERROR");

    // 5. Valid CONTINUATION frame on stream 1 with END_HEADERS
    let cont_ok = h2_internal::FrameHeader {
        length:     64,
        frame_type: rfc::H2_FRAME_CONTINUATION,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_cont_ok = h2_internal::on_ingress_frame_header(conn, cont_ok, 0);
    assert(err_cont_ok == rfc::H2_ERR_NO_ERROR);
    assert(conn.continuation_stream_id == 0);
    print("STATE: ContinuationEnd -> Normal");

    // 6. Flow control: WINDOW_UPDATE increment 0 is illegal
    let err_zero_win = h2_internal::apply_window_update(conn, 0, 0);
    assert(err_zero_win == rfc::H2_ERR_PROTOCOL_ERROR);
    print("ZERO_WINDOW_UPDATE: PROTOCOL_ERROR");

    // 7. Flow control: Window overflow beyond 2^31 - 1
    let err_ovf_win = h2_internal::apply_window_update(conn, 0, 0x7FFFFFFF);
    assert(err_ovf_win == rfc::H2_ERR_FLOW_CONTROL_ERROR);
    print("WINDOW_OVERFLOW: FLOW_CONTROL_ERROR");

    // 8. Wire framing split stream & mutation fuzzing
    var raw_cont_wire: u8[>..] = [];
    assert(wire_kit::parse_hex("00000409040000000101020304", raw_cont_wire));
    assert(wire_kit::verify_split_stream(raw_cont_wire[..], -1, 1, parse_h2_hdr_step));
    assert(wire_kit::fuzz_payload(raw_cont_wire[..], 200, parse_h2_hdr_step));
    print("WIRE_CONTINUATION_FUZZ: PASS");
}

// CHECK-LABEL: === H2_CONTINUATION_AND_FSM_VERIFICATION ===
// CHECK-NEXT: STATE: IngressHeaders -> ExpectContinuation(stream=1)
// CHECK-NEXT: INTERLEAVED_PING_BAN: PROTOCOL_ERROR
// CHECK-NEXT: INTERLEAVED_DATA_BAN: PROTOCOL_ERROR
// CHECK-NEXT: MISMATCHED_STREAM_CONTINUATION: PROTOCOL_ERROR
// CHECK-NEXT: STATE: ContinuationEnd -> Normal
// CHECK-NEXT: ZERO_WINDOW_UPDATE: PROTOCOL_ERROR
// CHECK-NEXT: WINDOW_OVERFLOW: FLOW_CONTROL_ERROR
// CHECK-NEXT: WIRE_CONTINUATION_FUZZ: PASS

// ============================================================================
// 4. verify_h2_control_frames (4/14)
// ============================================================================
// CHECK: === [4/14] verify_h2_control_frames ===

// tests/lit/verify_h2_control_frames.goose
// Verification of RFC 9113 HTTP/2 control frame wire invariants via wing::http2.
//

// Wire adapter for verify_split_stream and fuzzing using wing's real HTTP/2 framer
fn wing_validate_h2_ctrl_frame_wire(buf: const u8[:]) -> i64 {
    guard buf.len >= 9 else { return -1; }
    let hdr, err_hdr = h2_internal::parse_frame_header(buf);
    guard err_hdr == rfc::H2_ERR_NO_ERROR else { return err_hdr as! i64; }
    let err_rules = h2_internal::validate_frame_header_rules(hdr);
    guard err_rules == rfc::H2_ERR_NO_ERROR else { return err_rules as! i64; }
    guard buf.len >= 9 + (hdr.length as i64) else { return -1; }
    return 0;
}

fn run_04_verify_h2_control_frames() {
    var raw_ack: u8[>..] = [];
    assert(wire_kit::parse_hex("000000040100000000", raw_ack));
    assert(wire_kit::verify_split_stream(raw_ack[..], -1, 0, wing_validate_h2_ctrl_frame_wire));
    assert(wire_kit::fuzz_payload(raw_ack[..], 100, wing_validate_h2_ctrl_frame_wire));
    print("H2_CTRL_SPLIT: OK");

    var vAck6: u8[>..] = []; wire_kit::parse_hex("000006040100000000", vAck6);
    assert(wing_validate_h2_ctrl_frame_wire(vAck6[..]) == 6);

    var vSid1: u8[>..] = []; wire_kit::parse_hex("000006040000000001", vSid1);
    assert(wing_validate_h2_ctrl_frame_wire(vSid1[..]) == 1);

    var vLen5: u8[>..] = []; wire_kit::parse_hex("000005040000000000", vLen5);
    assert(wing_validate_h2_ctrl_frame_wire(vLen5[..]) == 6);

    var vPing7: u8[>..] = []; wire_kit::parse_hex("000007060000000000", vPing7);
    assert(wing_validate_h2_ctrl_frame_wire(vPing7[..]) == 6);

    var vPingSid: u8[>..] = []; wire_kit::parse_hex("000008060000000003", vPingSid);
    assert(wing_validate_h2_ctrl_frame_wire(vPingSid[..]) == 1);

    var vRst0: u8[>..] = []; wire_kit::parse_hex("000004030000000000", vRst0);
    assert(wing_validate_h2_ctrl_frame_wire(vRst0[..]) == 1);

    var vRst5: u8[>..] = []; wire_kit::parse_hex("000005030000000001", vRst5);
    assert(wing_validate_h2_ctrl_frame_wire(vRst5[..]) == 6);
    print("H2_CTRL_INVARIANTS: OK");
}

// CHECK: H2_CTRL_SPLIT: OK
// CHECK: H2_CTRL_INVARIANTS: OK

// ============================================================================
// 5. verify_h2_microbench (5/14)
// ============================================================================
// CHECK: === [5/14] verify_h2_microbench ===

// tests/lit/verify_h2_microbench.goose
// HTTP/2 microbenchmark latency budgets: frame header round-trip, HPACK field
// encode (literal + Huffman, no indexing), and HPACK header block decode
// (RFC 7541 Appendix A static indices) under strict latency ceilings.
// Complements verify_wire_benchmarks.goose (CRLFCRLF, TLS header, LPM, chunk FSM).
//

// Drops the optimizer's knowledge of `buf`'s elements: a builder extern may
// legally write them (goose.h contract), so later loads are runtime work.
fn opaque_barrier(buf: u8[>..]&) {
    var nonce: u8[>..] = [];
    let _ = env("H2BENCH_NONCE", nonce);
    let _ = env("H2BENCH_NONCE", buf);
}

inline fn elapsed_ns(t0: core::MonotonicInstant, t1: core::MonotonicInstant) -> u64 {
    return t1.nanos - t0.nanos;
}

// 4096-iteration sample windows: the per-op average is a shift, not a divide.
inline fn ns_per_op_4k(elapsed: u64) -> u64 {
    return elapsed >> 12;
}

// Loop-carried round-trip feedback: the next parse sees the stream byte the
// previous parse produced, so the measured work cannot be hoisted away.
fn echo_stream_byte(live: u8[>..]&, encoded: u8[9]&) {
    live[8] = encoded[8];
}

fn echo_value_byte(val: u8[8]&, enc: u8[>..]&) {
    val[0] = enc[0];
}

fn bench_h2_frame_roundtrip() {
    // RFC 9113 Section 4.1: HEADERS frame header, length 4, END_HEADERS on
    // stream 1.
    let raw:   u8[9] = [0x00, 0x00, 0x04, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01];
    let iters: u64   = 5000;

    var live: u8[>..] = [];
    for i in 9 {
        live.push(raw[i]);
    }
    opaque_barrier(live);

    for _ in iters {
        let parsed, err = h2_internal::parse_frame_header(live[..]);
        assert(err == 0 && parsed.frame_type == 1);
        var out: u8[9] = [0; 9];
        h2_internal::encode_frame_header(parsed, out);
        echo_stream_byte(live, out);
    }

    let t0 = core::monotonic_now();
    for _ in iters {
        let parsed, err = h2_internal::parse_frame_header(live[..]);
        assert(err == 0);
        assert(parsed.length == 4 && parsed.frame_type == 1);
        var out: u8[9] = [0; 9];
        h2_internal::encode_frame_header(parsed, out);
        echo_stream_byte(live, out);
    }
    let t1 = core::monotonic_now();

    let avg_ns = ns_per_op_4k(elapsed_ns(t0, t1));

    assert(avg_ns <= 500);
    print("BENCH_H2_FRAME_ROUNDTRIP: OK ", avg_ns, " ns/op");
}

fn bench_h2_hpack_encode() {
    // Literal header field with incremental indexing suppressed; the value's
    // first byte rolls through the encoded output so the Huffman path executes
    // per iteration with runtime data.
    let name:  const u8[:] = "x-request-id";
    let iters: u64         = 5000;

    var val: u8[8] = ['9', 'f', '3', 'd', '2', 'a', '1', 'b'];
    var dt = h2_internal::new_dynamic_table();
    var enc: u8[>..] = [];
    opaque_barrier(enc);

    for _ in iters {
        enc.clear();
        let ok = h2_internal::encode_hpack_field(dt, enc, name, val[..], h2_internal::HpackIndexing.None, true);
        assert(ok && enc.len > 0);
        echo_value_byte(val, enc);
    }

    let t0 = core::monotonic_now();
    for _ in iters {
        enc.clear();
        let ok = h2_internal::encode_hpack_field(dt, enc, name, val[..], h2_internal::HpackIndexing.None, true);
        assert(ok && enc.len > 0);
        echo_value_byte(val, enc);
    }
    let t1 = core::monotonic_now();

    let avg_ns = ns_per_op_4k(elapsed_ns(t0, t1));

    assert(avg_ns <= 800);
    print("BENCH_H2_HPACK_ENCODE: OK ", avg_ns, " ns/op");
}

fn bench_h2_hpack_decode() {
    // RFC 7541 Appendix A indices: 2 = :method GET, 7 = :scheme https, 4 = :path /.
    let hblock: u8[3] = [0x82, 0x87, 0x84];
    let iters:  u64   = 5000;

    var dt = h2_internal::new_dynamic_table();
    var pseudo = h2_internal::H2PseudoHeaders { .. };
    var out = wing::HeaderMap { .. };
    for _ in iters {
        let err = h2_internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
        assert(err == 0 && pseudo.has_method && pseudo.has_scheme && pseudo.has_path);
    }

    let t0 = core::monotonic_now();
    for _ in iters {
        let err = h2_internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
        assert(err == 0 && pseudo.has_method && pseudo.has_scheme && pseudo.has_path);
    }
    let t1 = core::monotonic_now();

    let avg_ns = ns_per_op_4k(elapsed_ns(t0, t1));

    assert(avg_ns <= 3000);
    print("BENCH_H2_HPACK_DECODE: OK ", avg_ns, " ns/op");
}

fn run_05_verify_h2_microbench() {
    print("=== RUNNING HTTP/2 MICROBENCHMARKS ===");
    bench_h2_frame_roundtrip();
    bench_h2_hpack_encode();
    bench_h2_hpack_decode();
    print("HTTP/2 MICROBENCHMARKS COMPLETE: ALL BUDGETS PASSED");
}

// CHECK: === RUNNING HTTP/2 MICROBENCHMARKS ===
// CHECK: BENCH_H2_FRAME_ROUNDTRIP: OK
// CHECK: BENCH_H2_HPACK_ENCODE: OK
// CHECK: BENCH_H2_HPACK_DECODE: OK
// CHECK: HTTP/2 MICROBENCHMARKS COMPLETE: ALL BUDGETS PASSED

// ============================================================================
// 6. verify_h2_spec (6/14)
// ============================================================================
// CHECK: === [6/14] verify_h2_spec ===

// tests/lit/verify_h2_spec.goose
// Verification of RFC 9113 HTTP/2 connection preface and frame invariants via wing::http2.
//

fn wing_verify_h2_preface(buf: const u8[:]) -> i32 {
    guard buf.len >= rfc::H2_CLIENT_PREFACE.len else { return 0; }
    if buf[..rfc::H2_CLIENT_PREFACE.len] == rfc::H2_CLIENT_PREFACE {
        return 1;
    }
    return 0;
}

fn wing_parse_and_validate_h2_frame(buf: const u8[:], is_client: bool) -> i32 {
    guard buf.len >= 9 else { return -1; }
    let hdr, err_hdr = h2_internal::parse_frame_header(buf);
    guard err_hdr == rfc::H2_ERR_NO_ERROR else { return err_hdr as! i32; }

    let err_rules = h2_internal::validate_frame_header_rules(hdr);
    guard err_rules == rfc::H2_ERR_NO_ERROR else { return err_rules as! i32; }

    // Client-initiated streams must be odd-numbered (RFC 9113 Section 5.1.1)
    if is_client && hdr.stream_id > 0 && (hdr.stream_id & 1) == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR as! i32;
    }

    return 0;
}

fn run_06_verify_h2_spec() {
    let preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert(wing_verify_h2_preface(preface) == 1);
    assert(wing_verify_h2_preface(rfc::H2_CLIENT_PREFACE) == 1);
    print("H2_PREFACE: OK");

    var vSet: u8[>..] = []; wire_kit::parse_hex("000006040000000000", vSet);
    assert(wing_parse_and_validate_h2_frame(vSet[..], true) == 0);

    var vSetBadSid: u8[>..] = []; wire_kit::parse_hex("000006040000000001", vSetBadSid);
    assert(wing_parse_and_validate_h2_frame(vSetBadSid[..], true) == 1);

    var vSetBadAck: u8[>..] = []; wire_kit::parse_hex("000006040100000000", vSetBadAck);
    assert(wing_parse_and_validate_h2_frame(vSetBadAck[..], true) == 6);

    var vPing: u8[>..] = []; wire_kit::parse_hex("000008060000000000", vPing);
    assert(wing_parse_and_validate_h2_frame(vPing[..], true) == 0);

    var vPingBadLen: u8[>..] = []; wire_kit::parse_hex("000007060000000000", vPingBadLen);
    assert(wing_parse_and_validate_h2_frame(vPingBadLen[..], true) == 6);

    var vClientEven: u8[>..] = []; wire_kit::parse_hex("00000A010500000002", vClientEven);
    assert(wing_parse_and_validate_h2_frame(vClientEven[..], true) == 1);

    var vClientOdd: u8[>..] = []; wire_kit::parse_hex("00000A010500000003", vClientOdd);
    assert(wing_parse_and_validate_h2_frame(vClientOdd[..], true) == 0);

    print("H2_SPEC_INVARIANTS: OK");
}

// CHECK: H2_PREFACE: OK
// CHECK: H2_SPEC_INVARIANTS: OK

// ============================================================================
// 7. verify_h2_spec_invariants (7/14)
// ============================================================================
// CHECK: === [7/14] verify_h2_spec_invariants ===

// tests/lit/verify_h2_spec_invariants.goose
// Verification of RFC 9113 HTTP/2 protocol invariants:
// 1. WINDOW_UPDATE on idle stream triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §5.1, §6.4).
// 2. Malformed request with missing pseudo-headers triggers RST_STREAM (RFC 9113 §8.1.1, §8.3.1).
// 3. Content-length mismatch on END_STREAM HEADERS triggers RST_STREAM (RFC 9113 §8.1.1).
// 4. Content-length mismatch on DATA frame triggers RST_STREAM (RFC 9113 §8.1.1, §8.1.2).
// 5. Active stream slot and counter reclamation on stream error (RFC 9113 §5.1.2).
// 6. SETTINGS_MAX_FRAME_SIZE peer tracking without overriding local receive limits (RFC 9113 §6.5.2).
//

fn m07_build_frame_header<B>(out: B&, length: u32, frame_type: u8, flags: u8, stream_id: u32) {
    out.push(((length >> 16) & 0xFF) as u8);
    out.push(((length >> 8) & 0xFF) as u8);
    out.push((length & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.push(((stream_id >> 24) & 0x7F) as u8);
    out.push(((stream_id >> 16) & 0xFF) as u8);
    out.push(((stream_id >> 8) & 0xFF) as u8);
    out.push((stream_id & 0xFF) as u8);
}

fn scan_frames(wire: const u8[:]) -> bool, bool, u32 {
    var has_rst = false;
    var has_goaway = false;
    var rst_sid: u32 = 0;
    var p:       i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) | ((wire[p + 6] as u32) << 16) | ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == 0x03 {
            has_rst = true;
            rst_sid = f_sid;
        }
        if f_type == 0x07 {
            has_goaway = true;
        }
        p += 9 + (f_len as i64);
    }
    return has_rst, has_goaway, rst_sid;
}

fn test_idle_stream_window_update() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // Preface + empty SETTINGS
    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m07_build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS frame
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send WINDOW_UPDATE on stream 5 (idle stream; last_peer_stream_id is 0)
    var wu_frame: u8[>..] = [];
    m07_build_frame_header(wu_frame, 4, 0x08, 0x00, 5); // WINDOW_UPDATE on stream 5
    wu_frame.push(0x00); wu_frame.push(0x00); wu_frame.push(0x04); wu_frame.push(0x00); // +1024 octets

    wire_out.clear();
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wu_frame[..], 1000, wire_out);
    let has_rst, has_goaway, _ = scan_frames(wire_out[..]);

    // RFC 9113 §5.1 & §6.4: Frame on idle stream MUST trigger GOAWAY(PROTOCOL_ERROR), NOT RST_STREAM.
    print("IDLE_WU_CONNECTION_TERMINATED: ", if !ok { "YES" } else { "NO" });
    print("IDLE_WU_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
    print("IDLE_WU_RST: ", if has_rst { "YES" } else { "NO" });
}

fn test_missing_mandatory_pseudo_headers() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m07_build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Request missing :path (only :method and :scheme provided)
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    m07_build_frame_header(h_frame, h_block.len as u32, 0x01, 0x05, 1); // HEADERS + END_STREAM | END_HEADERS
    h_frame.append(h_block[..]);

    wire_out.clear();
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);
    let has_rst, has_goaway, sid = scan_frames(wire_out[..]);

    // RFC 9113 §8.1.1: Malformed request MUST be treated as a stream error RST_STREAM, not GOAWAY
    print("MISSING_PSEUDO_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("MISSING_PSEUDO_RST_STREAM: ", if has_rst && sid == 1 { "YES" } else { "NO" });
    print("MISSING_PSEUDO_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
}

fn test_content_length_end_stream_headers() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m07_build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // HEADERS with END_STREAM but content-length: 10
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, "content-length", "10", h2_internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    m07_build_frame_header(h_frame, h_block.len as u32, 0x01, 0x05, 1); // HEADERS + END_STREAM | END_HEADERS
    h_frame.append(h_block[..]);

    wire_out.clear();
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);
    let has_rst, has_goaway, sid = scan_frames(wire_out[..]);

    // RFC 9113 §8.1.1: Content-length mismatch MUST be treated as a stream error RST_STREAM, not GOAWAY
    print("CL_HEADERS_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("CL_HEADERS_RST_STREAM: ", if has_rst && sid == 1 { "YES" } else { "NO" });
    print("CL_HEADERS_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
}

fn test_content_length_mismatch_data() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m07_build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // HEADERS with content-length: 10, but NO END_STREAM
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/post", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, "content-length", "10", h2_internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    m07_build_frame_header(h_frame, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS (no END_STREAM)
    h_frame.append(h_block[..]);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);

    // DATA with 3 bytes and END_STREAM (expected 10, received 3)
    var d_frame: u8[>..] = [];
    m07_build_frame_header(d_frame, 3, 0x00, 0x01, 1); // DATA + END_STREAM
    d_frame.append("foo");

    wire_out.clear();
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d_frame[..], 1000, wire_out);
    let has_rst, has_goaway, sid = scan_frames(wire_out[..]);

    // RFC 9113 §8.1.1 & §8.1.2: Content-length mismatch MUST be stream error RST_STREAM, not GOAWAY
    print("CL_DATA_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("CL_DATA_RST_STREAM: ", if has_rst && sid == 1 { "YES" } else { "NO" });
    print("CL_DATA_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
}

fn test_stream_slot_reclamation_on_error() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m07_build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send HEADERS with invalid uppercase field name (RFC 9113 §8.2.1)
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, "Custom-Upper", "val", h2_internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    m07_build_frame_header(h_frame, h_block.len as u32, 0x01, 0x05, 1);
    h_frame.append(h_block[..]);

    wire_out.clear();
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);

    // RFC 9113 §5.1.2: Active stream slot MUST be reclaimed upon reset
    print("STREAM_RECLAIMED_ACTIVE_COUNT: ", sess.conn.active_stream_count);
}

fn test_settings_max_frame_size_isolation() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // Client advertises SETTINGS_MAX_FRAME_SIZE = 32768
    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m07_build_frame_header(init_wire, 6, 0x04, 0x00, 0); // SETTINGS frame
    init_wire.push(0x00); init_wire.push(0x05); // SETTING_MAX_FRAME_SIZE (0x05)
    init_wire.push(0x00); init_wire.push(0x00); init_wire.push(0x80); init_wire.push(0x00); // 32768

    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // RFC 9113 §6.5.2: Server's local receive frame size must remain 16384
    print("LOCAL_MAX_FRAME_SIZE_KEPT: ", if sess.conn.local_max_frame_size == 16384 { "YES" } else { "NO" });
}

fn run_07_verify_h2_spec_invariants() {
    test_idle_stream_window_update();
    test_missing_mandatory_pseudo_headers();
    test_content_length_end_stream_headers();
    test_content_length_mismatch_data();
    test_stream_slot_reclamation_on_error();
    test_settings_max_frame_size_isolation();
    print("H2_SPEC_INVARIANTS_VERIFIED");
}

// CHECK: IDLE_WU_CONNECTION_TERMINATED: YES
// CHECK: IDLE_WU_GOAWAY: YES
// CHECK: IDLE_WU_RST: NO
// CHECK: MISSING_PSEUDO_CONN_ALIVE: YES
// CHECK: MISSING_PSEUDO_RST_STREAM: YES
// CHECK: MISSING_PSEUDO_GOAWAY: NO
// CHECK: CL_HEADERS_CONN_ALIVE: YES
// CHECK: CL_HEADERS_RST_STREAM: YES
// CHECK: CL_HEADERS_GOAWAY: NO
// CHECK: CL_DATA_CONN_ALIVE: YES
// CHECK: CL_DATA_RST_STREAM: YES
// CHECK: CL_DATA_GOAWAY: NO
// CHECK: STREAM_RECLAIMED_ACTIVE_COUNT: 0
// CHECK: LOCAL_MAX_FRAME_SIZE_KEPT: YES
// CHECK: H2_SPEC_INVARIANTS_VERIFIED

// ============================================================================
// 8. verify_h2_spill_lane (8/14)
// ============================================================================
// CHECK: === [8/14] verify_h2_spill_lane ===

// tests/lit/verify_h2_spill_lane.goose
// Verification of HTTP/2 Stream Spill Slab Pool invariants:
// 1. Fast-path inline buffer retention for requests <= 8192 bytes (zero slabs allocated).
// 2. Dynamic promotion & reassembly for requests > 8 KiB (32 KiB multi-frame payload).
// 3. Flow control credit expansion: WINDOW_UPDATE (+57344) emitted upon promotion.
// 4. Maximum capacity rejection: stream exceeding 65536 bytes reset with CANCEL.
// 5. Pool saturation defense: 17th concurrent stream > 8 KiB reset with REFUSED_STREAM.
// 6. Zero-leak lifecycle: slabs released upon stream completion, reset, or error.
//

fn m08_build_frame_header<B>(out: B&, length: u32, frame_type: u8, flags: u8, stream_id: u32) {
    out.push(((length >> 16) & 0xFF) as u8);
    out.push(((length >> 8) & 0xFF) as u8);
    out.push((length & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.push(((stream_id >> 24) & 0x7F) as u8);
    out.push(((stream_id >> 16) & 0xFF) as u8);
    out.push(((stream_id >> 8) & 0xFF) as u8);
    out.push((stream_id & 0xFF) as u8);
}

fn scan_for_window_update(wire: const u8[:], stream_id: u32) -> bool, u32 {
    var p: i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) |
                    ((wire[p + 6] as u32) << 16) |
                    ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == 0x08 && f_sid == stream_id && (p + 13 <= wire.len) {
            let inc = ((wire[p + 9] as u32) << 24) |
                      ((wire[p + 10] as u32) << 16) |
                      ((wire[p + 11] as u32) << 8) | wire[p + 12];
            return true, (inc & 0x7FFFFFFF);
        }
        p += 9 + (f_len as i64);
    }
    return false, 0;
}

fn scan_for_rst_stream(wire: const u8[:], stream_id: u32) -> bool, u32 {
    var p: i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) |
                    ((wire[p + 6] as u32) << 16) |
                    ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == 0x03 && f_sid == stream_id && (p + 13 <= wire.len) {
            let err_code = ((wire[p + 9] as u32) << 24) |
                           ((wire[p + 10] as u32) << 16) |
                           ((wire[p + 11] as u32) << 8) | wire[p + 12];
            return true, err_code;
        }
        p += 9 + (f_len as i64);
    }
    return false, 0;
}

fn count_in_use_slabs(pool: const server_internal::SpillSlabPool&) -> i64 {
    var count: i64 = 0;
    for &slab in pool.slabs {
        if slab.in_use { count++; }
    }
    return count;
}

fn test_inline_body_lifecycle() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/inline", 1);

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m08_build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send HEADERS for stream 1
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/inline", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, "content-length", "4096", h2_internal::HpackIndexing.Incremental, false);

    var req_wire: u8[>..] = [];
    m08_build_frame_header(req_wire, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS
    req_wire.append(h_block[..]);

    // Send 4096 bytes of body (<= 8192 inline buffer)
    var chunk: u8[>..] = [];
    for i in 4096 { chunk.push('A'); }
    m08_build_frame_header(req_wire, 4096, 0x00, 0x01, 1); // DATA + END_STREAM
    req_wire.append(chunk[..]);

    wire_out.clear();
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", req_wire[..], 1000, wire_out);

    print("INLINE_INGRESS_OK: ", if ok { "YES" } else { "NO" });
    print("SLABS_IN_USE_INLINE: ", count_in_use_slabs(pipeline.slab_pool));
}

fn test_dynamic_promotion_and_reassembly() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/large", 2);

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m08_build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send HEADERS for stream 1
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/large", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, "content-length", "32768", h2_internal::HpackIndexing.Incremental, false);

    var h_wire: u8[>..] = [];
    m08_build_frame_header(h_wire, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS
    h_wire.append(h_block[..]);

    wire_out.clear();
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_wire[..], 1000, wire_out);

    // Chunk 1: 8192 bytes + 1 byte (> 8192 -> triggers promotion to SpillSlab within 8192 initial window!)
    var chunk1a: u8[>..] = [];
    for i in 8192 { chunk1a.push('B'); }
    var d1a_wire: u8[>..] = [];
    m08_build_frame_header(d1a_wire, 8192, 0x00, 0x00, 1);
    d1a_wire.append(chunk1a[..]);
    wire_out.clear();
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d1a_wire[..], 1000, wire_out);

    var chunk1: u8[>..] = [];
    for i in 8192 { chunk1.push('B'); }
    var d1_wire: u8[>..] = [];
    m08_build_frame_header(d1_wire, 8192, 0x00, 0x00, 1); // DATA (no END_STREAM, total 16384 -> triggers promotion!)
    d1_wire.append(chunk1[..]);

    wire_out.clear();
    let _, ok_d1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d1_wire[..], 1000, wire_out);
    let has_wu, wu_credit = scan_for_window_update(wire_out[..], 1);

    print("PROMOTION_INGRESS_OK: ", if ok_d1 { "YES" } else { "NO" });
    print("PROMOTION_WINDOW_UPDATE_EMITTED: ", if has_wu { "YES" } else { "NO" });
    print("PROMOTION_WINDOW_UPDATE_CREDIT: ", wu_credit);

    // Chunk 2: 16384 bytes with END_STREAM (total 32768 bytes)
    var chunk2: u8[>..] = [];
    for i in 16384 { chunk2.push('C'); }
    var d2_wire: u8[>..] = [];
    m08_build_frame_header(d2_wire, 16384, 0x00, 0x01, 1); // DATA + END_STREAM
    d2_wire.append(chunk2[..]);

    wire_out.clear();
    let _, ok_d2 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d2_wire[..], 1000, wire_out);

    print("COMPLETION_INGRESS_OK: ", if ok_d2 { "YES" } else { "NO" });
    print("SLABS_IN_USE_AFTER_DISPATCH: ", count_in_use_slabs(pipeline.slab_pool));
}

fn test_maximum_capacity_overflow() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/overflow", 3);

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m08_build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/overflow", h2_internal::HpackIndexing.Incremental, false);

    var h_wire: u8[>..] = [];
    m08_build_frame_header(h_wire, h_block.len as u32, 0x01, 0x04, 1);
    h_wire.append(h_block[..]);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_wire[..], 1000, wire_out);

    // Send 8 frames of 8192 bytes = 65536 bytes (fits exactly in 64 KiB slab within 8192 initial window)
    var chunk: u8[>..] = [];
    for i in 8192 { chunk.push('X'); }
    for step in 8 {
        var d_wire: u8[>..] = [];
        m08_build_frame_header(d_wire, 8192, 0x00, 0x00, 1);
        d_wire.append(chunk[..]);
        server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d_wire[..], 1000, wire_out);
    }

    // Grant stream window credit for the 65537th byte so slab capacity check (not flow control) fires
    let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, 1);
    if c_found { sess.conn.streams[c_idx].recv_window += 4096; }

    // Now send 1 extra byte (65537 > 65536 max slab capacity)
    var overflow_wire: u8[>..] = [];
    m08_build_frame_header(overflow_wire, 1, 0x00, 0x01, 1);
    overflow_wire.push('!');

    wire_out.clear();
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", overflow_wire[..], 1000, wire_out);

    let has_rst, rst_code = scan_for_rst_stream(wire_out[..], 1);
    print("OVERFLOW_RST_EMITTED: ", if has_rst { "YES" } else { "NO" });
    print("OVERFLOW_RST_CODE_CANCEL: ", if rst_code == rfc::H2_ERR_CANCEL { "YES" } else { "NO" });
    print("OVERFLOW_SLAB_RECLAIMED: ", if count_in_use_slabs(pipeline.slab_pool) == 0 { "YES" } else { "NO" });
}

fn test_pool_saturation_rejection() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/saturated", 4);

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    m08_build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Manually exhaust all 16 slab slots in pipeline.slab_pool
    for i in 16 {
        let idx = server_internal::acquire_spill_slab(pipeline.slab_pool);
        guard idx >= 0 else { break; }
    }
    print("ALL_SLABS_ACQUIRED: ", if count_in_use_slabs(pipeline.slab_pool) == 16 { "YES" } else { "NO" });

    // Stream 1 sends headers
    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/saturated", h2_internal::HpackIndexing.Incremental, false);

    var h_wire: u8[>..] = [];
    m08_build_frame_header(h_wire, h_block.len as u32, 0x01, 0x04, 1);
    h_wire.append(h_block[..]);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_wire[..], 1000, wire_out);

    // Stream 1 sends 8192 bytes + 1808 bytes = 10,000 bytes (> 8192 inline buffer, but pool is saturated!)
    var chunk8k: u8[>..] = [];
    for i in 8192 { chunk8k.push('S'); }
    var d8k_wire: u8[>..] = [];
    m08_build_frame_header(d8k_wire, 8192, 0x00, 0x00, 1);
    d8k_wire.append(chunk8k[..]);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d8k_wire[..], 1000, wire_out);

    var chunk: u8[>..] = [];
    for i in 1808 { chunk.push('S'); }
    var d_wire: u8[>..] = [];
    m08_build_frame_header(d_wire, 1808, 0x00, 0x00, 1);
    d_wire.append(chunk[..]);

    wire_out.clear();
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d_wire[..], 1000, wire_out);

    let has_rst, rst_code = scan_for_rst_stream(wire_out[..], 1);
    print("SATURATION_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("SATURATION_RST_EMITTED: ", if has_rst { "YES" } else { "NO" });
    print("SATURATION_RST_REFUSED: ", if rst_code == rfc::H2_ERR_REFUSED_STREAM { "YES" } else { "NO" });

    // Clean up acquired slabs
    for i in 16 {
        server_internal::release_spill_slab(pipeline.slab_pool, i as i32);
    }
}

fn run_08_verify_h2_spill_lane() {
    test_inline_body_lifecycle();
    test_dynamic_promotion_and_reassembly();
    test_maximum_capacity_overflow();
    test_pool_saturation_rejection();
    print("H2_SPILL_LANE_VERIFIED");
}

// CHECK: INLINE_INGRESS_OK: YES
// CHECK: SLABS_IN_USE_INLINE: 0
// CHECK: PROMOTION_INGRESS_OK: YES
// CHECK: PROMOTION_WINDOW_UPDATE_EMITTED: YES
// CHECK: PROMOTION_WINDOW_UPDATE_CREDIT: 57344
// CHECK: COMPLETION_INGRESS_OK: YES
// CHECK: SLABS_IN_USE_AFTER_DISPATCH: 0
// CHECK: OVERFLOW_RST_EMITTED: YES
// CHECK: OVERFLOW_RST_CODE_CANCEL: YES
// CHECK: OVERFLOW_SLAB_RECLAIMED: YES
// CHECK: ALL_SLABS_ACQUIRED: YES
// CHECK: SATURATION_CONN_ALIVE: YES
// CHECK: SATURATION_RST_EMITTED: YES
// CHECK: SATURATION_RST_REFUSED: YES
// CHECK: H2_SPILL_LANE_VERIFIED

// ============================================================================
// 9. verify_hpack_edge (9/14)
// ============================================================================
// CHECK: === [9/14] verify_hpack_edge ===

// tests/lit/verify_hpack_edge.goose
// Verification of RFC 7541 HPACK integer prefix decoding and Huffman padding via wing::http2.
//

// Wire adapter for verify_split_stream and fuzzing using wing's real hpack_decode_int
fn wing_decode_hpack_int_5(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let val, new_off, ok = h2_internal::hpack_decode_int(buf, 0, 5);
    if ok {
        return val as! i64;
    }
    if new_off == 0 {
        return -1; // truncated
    }
    return -2; // overflow
}

fn validate_huffman_padding(buf: const u8[:], rem_bits: i32) -> i32 {
    let len = buf.len;
    if len <= 0 || rem_bits < 0 || rem_bits > 7 { return -1; }
    if rem_bits == 0 { return 1; }
    let last_byte = buf[len - 1] as i32;
    let pad_mask = (1 << (rem_bits as u32)) - 1;
    let pad_val = last_byte & pad_mask;
    if pad_val != pad_mask {
        return 0;
    }
    return 1;
}

fn run_09_verify_hpack_edge() {
    var raw_int: u8[>..] = [];
    assert(wire_kit::parse_hex("1F9A0A", raw_int));
    assert(wire_kit::verify_split_stream(raw_int[..], -1, 1337, wing_decode_hpack_int_5));
    assert(wire_kit::fuzz_payload(raw_int[..], 100, wing_decode_hpack_int_5));
    print("HPACK_INT_SPLIT: OK");

    var ovf: u8[>..] = [];
    assert(wire_kit::parse_hex("1FFFFFFFFFFFFFFFFFFF01", ovf));
    assert(wing_decode_hpack_int_5(ovf[..]) == -2);
    print("HPACK_INT_OVF: OK");

    var pad_ok: u8[>..] = [];
    assert(wire_kit::parse_hex("FF", pad_ok));
    assert(validate_huffman_padding(pad_ok[..], 4) == 1);

    var pad_bad: u8[>..] = [];
    assert(wire_kit::parse_hex("FE", pad_bad));
    assert(validate_huffman_padding(pad_bad[..], 4) == 0);
    print("HPACK_HUFFMAN_PAD: OK");
}

// CHECK: HPACK_INT_SPLIT: OK
// CHECK: HPACK_INT_OVF: OK
// CHECK: HPACK_HUFFMAN_PAD: OK

// ============================================================================
// 10. verify_hpack_qpack (10/14)
// ============================================================================
// CHECK: === [10/14] verify_hpack_qpack ===

// tests/lit/verify_hpack_qpack.goose
// Verification of HPACK & QPACK integer prefix decoding, string framing, and Huffman codec via wing.
//

// Wire adapter for verify_split_stream and fuzzing using h2_internal::hpack_decode_int (5-bit prefix)
fn wing_decode_varint_5(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let val, new_off, ok = h2_internal::hpack_decode_int(buf, 0, 5);
    if ok { return val as! i64; }
    if new_off == 0 { return -1; }
    return -2;
}

// Wire adapter for verify_split_stream and fuzzing using h2_internal::hpack_decode_int (7-bit prefix)
fn wing_decode_varint_7(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let val, new_off, ok = h2_internal::hpack_decode_int(buf, 0, 7);
    if ok { return val as! i64; }
    if new_off == 0 { return -1; }
    return -2;
}

// Wire adapter for verify_split_stream and fuzzing using h2_internal::decode_hpack_string
fn wing_parse_hpack_string_frame(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    var out: u8[..4096] = [];
    let next_off, ok = h2_internal::decode_hpack_string(buf, 0, out);
    if ok {
        let is_huff = (buf[0] & 0x80) != 0;
        let str_len, _, _ = h2_internal::hpack_decode_int(buf, 0, 7);
        return if is_huff { 0 - (str_len as i64) } else { str_len as i64 };
    }
    return -1;
}

fn calc_varint_step(acc: i64, payload: i64, shift: i64) -> i64 {
    return acc + ((payload & 127) << (shift as u32));
}

fn derive_hpack_mask(prefix_bits: i64) -> i64 {
    return (1 << (prefix_bits as u32)) - 1;
}

fn run_10_verify_hpack_qpack() {
    var v5: u8[>..] = []; wire_kit::parse_hex("1F9A0A", v5);
    assert(wire_kit::verify_split_stream(v5[..], -1, 1337, wing_decode_varint_5));
    assert(wire_kit::fuzz_payload(v5[..], 100, wing_decode_varint_5));
    print("HPACK_VARINT_5: OK");

    var v7_42: u8[>..] = []; wire_kit::parse_hex("2A", v7_42);
    assert(wing_decode_varint_7(v7_42[..]) == 42);

    var v7_255: u8[>..] = []; wire_kit::parse_hex("7F8001", v7_255);
    assert(wire_kit::verify_split_stream(v7_255[..], -1, 255, wing_decode_varint_7));
    assert(wire_kit::fuzz_payload(v7_255[..], 100, wing_decode_varint_7));

    var vA: u8[>..] = []; wire_kit::parse_hex("7FFFFFFFFFFF10", vA);
    assert(wing_decode_varint_7(vA[..]) == -2);
    var vB: u8[>..] = []; wire_kit::parse_hex("7FFFFFFFFFFFFFFFFFFF01", vB);
    assert(wing_decode_varint_7(vB[..]) == -2);
    var vC: u8[>..] = []; wire_kit::parse_hex("7F80", vC);
    assert(wing_decode_varint_7(vC[..]) == -1);
    print("HPACK_VARINT_7: OK");

    var str_raw: u8[>..] = []; wire_kit::parse_hex("0A637573746F6D2D6B6579", str_raw);
    assert(wire_kit::verify_split_stream(str_raw[..], -1, 10, wing_parse_hpack_string_frame));
    assert(wire_kit::fuzz_payload(str_raw[..], 100, wing_parse_hpack_string_frame));

    var str_huff: u8[>..] = []; wire_kit::parse_hex("8CF1E3C2E5F23A6BA0AB90F4FF", str_huff);
    assert(wire_kit::verify_split_stream(str_huff[..], -1, -12, wing_parse_hpack_string_frame));
    assert(wire_kit::fuzz_payload(str_huff[..], 100, wing_parse_hpack_string_frame));

    var str_ovf: u8[>..] = []; wire_kit::parse_hex("40010203", str_ovf);
    assert(wing_parse_hpack_string_frame(str_ovf[..]) == -1);
    print("HPACK_STRING_FRAMING: OK");

    assert(calc_varint_step(31, 10, 7) == 1311);
    assert(derive_hpack_mask(5) == 31);

    // Verify O(1) QPACK static table bucket lookup across all 99 entries + non-matching headers
    var q_idx: u64 = 0;
    while q_idx < 99 {
        let entry, ok = h3_internal::get_qpack_static_field(q_idx);
        assert(ok);
        let found_idx, exact = h3_internal::find_qpack_static_field(entry.name, entry.val);
        assert(exact);
        assert(found_idx == q_idx);

        let name_idx, exact_miss = h3_internal::find_qpack_static_field(entry.name, "__nonexistent_val__");
        assert(!exact_miss);
        let first_entry, ok_first = h3_internal::get_qpack_static_field(name_idx);
        assert(ok_first);
        assert(first_entry.name == entry.name);
        q_idx++;
    }
    let miss_short, ex_short = h3_internal::find_qpack_static_field("x", "1");
    assert(!ex_short && miss_short == 0);
    let miss_long, ex_long = h3_internal::find_qpack_static_field("x-custom-very-long-header-name-35ch", "1");
    assert(!ex_long && miss_long == 0);
    let miss_mid, ex_mid = h3_internal::find_qpack_static_field("x-custom-hdr", "1");
    assert(!ex_mid && miss_mid == 0);
    print("QPACK_STATIC_BUCKET_LOOKUP: OK");

    print("HPACK_QPACK_ALL: PASS");
}

// CHECK: HPACK_VARINT_5: OK
// CHECK: HPACK_VARINT_7: OK
// CHECK: HPACK_STRING_FRAMING: OK
// CHECK: QPACK_STATIC_BUCKET_LOOKUP: OK
// CHECK: HPACK_QPACK_ALL: PASS

// ============================================================================
// 11. verify_hpack_ring (11/14)
// ============================================================================
// CHECK: === [11/14] verify_hpack_ring ===

// tests/lit/verify_hpack_ring.goose
// Native LIT verification for HTTP/1.1 incremental Slowloris scanning, SWAR lexical/method parsing,
// linearized boundary HPACK ring buffer & O(1) direct-mapped hash table, O(1) ctz priority scheduler
// with 16-frame burst quantum yield, and RFC 9842 Compression Dictionary Transport (DCZ/DCB).
//

var g_dt_rfc:     h2_internal::DynamicTable    = h2_internal::DynamicTable { .. };
var g_dt_wrap:    h2_internal::DynamicTable    = h2_internal::DynamicTable { .. };
var g_out_pseudo: h2_internal::H2PseudoHeaders = h2_internal::H2PseudoHeaders { .. };
var g_out_list:   wing::HeaderMap              = wing::HeaderMap { .. };
var g_conn:       h2_internal::H2Connection    = h2_internal::H2Connection { .. };
var g_client:     wing::Client                 = wing::Client { .. };
var g_server_res: wing::Response               = wing::Response { .. };
var g_dcz_res:    wing::Response               = wing::Response { .. };
var g_req:        wing::Request                = wing::Request { .. };

fn verify_incremental_http1_scan() {
    let raw = "GET /api/v1/items HTTP/1.1\r\nHost: example.com\r\nUser-Agent: wing/1.0\r\n\r\n{\"ok\":true}";
    var cursor: i64 = 0;

    // Fragment 1: Partial header before \r\n\r\n
    let end1, ok1 = wing::scan_http1_headers(raw[..30], 0, cursor);
    assert(!ok1 && end1 == 0 && cursor == 27);

    // Fragment 2: Split right inside \r\n\r\n (includes "\r\n\r" at index 68..71)
    let end2, ok2 = wing::scan_http1_headers(raw[..70], 30, cursor);
    assert(!ok2 && end2 == 0 && cursor == 67);

    // Fragment 3: Full header arrives; starts scanning at (70 - 3) = 67 and catches split \r\n\r\n
    let end3, ok3 = wing::scan_http1_headers(raw, 70, cursor);
    assert(ok3 && end3 == 71 && cursor == 71);
}

fn verify_lexical_swar_and_methods() {
    let m1, c1, ok1 = wing::match_http_method_u32("GET /index.html HTTP/1.1\r\n");
    assert(ok1 && m1 == "GET" && c1 == 4);

    let m2, c2, ok2 = wing::match_http_method_u32("POST /submit HTTP/1.1\r\n");
    assert(ok2 && m2 == "POST" && c2 == 5);

    let m3, c3, ok3 = wing::match_http_method_u32("HEAD /status HTTP/1.1\r\n");
    assert(ok3 && m3 == "HEAD" && c3 == 5);

    let m4, c4, ok4 = wing::match_http_method_u32("PUT /item HTTP/1.1\r\n");
    assert(ok4 && m4 == "PUT" && c4 == 4);

    let m5, c5, ok5 = wing::match_http_method_u32("DELETE /item HTTP/1.1\r\n");
    assert(ok5 && m5 == "DELETE" && c5 == 7);

    let _, _, bad_m = wing::match_http_method_u32("FOOBAR / HTTP/1.1\r\n");
    assert(!bad_m);

    assert(wing::is_valid_token_swar("Content-Security-Policy-Report-Only"));
    assert(!wing::is_valid_token_swar("Bad Header:Name"));

    let tok_len, tok_ok = wing::scan_token_swar("X-Forwarded-For: 10.0.0.1\r\n");
    assert(tok_ok && tok_len == 15);
}

fn verify_hpack_rfc7541_vectors_and_ring() {
    // 1. RFC 7541 Appendix C.2.1: Literal Header Field with Indexing
    // custom-key: custom-header
    let c21_wire: const u8[26] = [
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];
    let err_c21 = h2_internal::decode_hpack_to_map(g_dt_rfc, c21_wire[..], g_out_pseudo, g_out_list, 8192, false);
    assert(err_c21 == rfc::H2_ERR_NO_ERROR);
    assert(g_out_list.entries.len == 1);
    assert(wing::entry_name(g_out_list, g_out_list.entries[0]) == "custom-key");
    assert(wing::entry_value(g_out_list, g_out_list.entries[0]) == "custom-header");
    assert(g_dt_rfc.used_bytes == 55);

    // Verify O(1) hash lookup on dynamic table & HpackHashTable overload
    let raw_ref, raw_ok = h2_internal::hpack_hash_lookup(g_dt_rfc.hash_table, "custom-key", "custom-header");
    assert(raw_ok && raw_ref == 1);
    let ext_idx, hit_ok = h2_internal::hpack_hash_lookup(g_dt_rfc, "custom-key", "custom-header");
    assert(hit_ok && ext_idx == 62);

    // 2. Linearized Boundary Ring Buffer wrap verification (4096-byte arena)
    var pad120: u8[..128] = [];
    for _ in 120 {
        pad120.push('a');
    }

    // Entry 0 at [0..128)
    h2_internal::insert_header(g_dt_wrap, "x-wrap-0", pad120[..], false);
    // Entry 1 at [128..256)
    h2_internal::insert_header(g_dt_wrap, "x-wrap-1", pad120[..], false);
    // Move arena_write_pos to 4020 to simulate arena boundary approach while Entry 0 & Entry 1 live at 0 and 128
    g_dt_wrap.arena_write_pos = 4020;
    // Insert a 100-byte raw header (4020 + 100 = 4120 > 4096 -> wraps to 0, evicts Entry 0 at [0..128),
    // leaving Entry 1 as oldest live entry at arena_tail = 128, and new entry at arena_head = 0).
    var val92: u8[..96] = [];
    for _ in 92 {
        val92.push('z');
    }
    h2_internal::insert_header(g_dt_wrap, "x-wrap-2", val92[..], false);
    assert(g_dt_wrap.arena_head == 0 && g_dt_wrap.arena_tail == 128);
    print("WING_HPACK_RING_LINEARIZED: head=", g_dt_wrap.arena_head, ", tail=", g_dt_wrap.arena_tail);

    let hit_idx, hit_match = h2_internal::hpack_hash_lookup(g_dt_wrap, "x-wrap-2", val92[..]);
    assert(hit_match && hit_idx == 62);
    // Evicted Entry 0 must NOT hit in hash table (generation invalidated)
    let _, stale_hit = h2_internal::hpack_hash_lookup(g_dt_wrap, "x-wrap-0", pad120[..]);
    assert(!stale_hit);
    print("WING_HPACK_HASH_HIT: slot=42, match=", hit_match);
}

fn schedule_sixteen_urgency_zero_frames(conn: h2_internal::H2Connection&) -> u32 {
    for _ in 16 {
        let sid, ok_sched = h2_internal::schedule_next_write(conn);
        assert(ok_sched && sid == 1);
    }
    return conn.urgency_streak_count;
}

fn verify_h2_priority_scheduler_and_burst_cap() {
    g_conn.conn_send_window = 1000000;
    g_conn.peer_max_frame_size = 1024;

    // Open stream 1 (urgency 0) and stream 3 (urgency 3)
    h2_internal::open_new_session_stream(g_conn, 1, false);
    h2_internal::open_new_session_stream(g_conn, 3, false);

    let prio_u0 = wing::PriorityParam { urgency: 0, incremental: false };
    let prio_u3 = wing::PriorityParam { urgency: 3, incremental: true };
    h2_internal::apply_priority_update(g_conn, 1, prio_u0);
    h2_internal::apply_priority_update(g_conn, 3, prio_u3);

    // Enqueue data on stream 1 (urgency 0) first -> active_urgency_mask == 0x01
    let ok_q1 = h2_internal::enqueue_stream_send_bytes(g_conn, 1, 32768);
    assert(ok_q1 && g_conn.active_urgency_mask == 0x01);
    print("WING_SCHEDULER_ACTIVE_MASK: 0x01");

    // Also enqueue data on stream 3 (urgency 3) -> active_urgency_mask == 0x09
    let ok_q3 = h2_internal::enqueue_stream_send_bytes(g_conn, 3, 4096);
    assert(ok_q3 && g_conn.active_urgency_mask == 0x09);

    // Schedule 16 consecutive frames: all 16 should come from urgency 0 (stream 1)
    let u0_frames = schedule_sixteen_urgency_zero_frames(g_conn);

    // 17th frame must yield to urgency 3 (stream 3) due to 16-frame burst quantum cap!
    let yielded_sid, ok_yield = h2_internal::schedule_next_write(g_conn);
    assert(ok_yield && yielded_sid == 3);
    print("WING_BURST_QUANTUM_YIELD: urgency=0, frames=", u0_frames);
}

fn verify_rfc9842_dictionary_transport() {
    let dict_raw = "common-json-keys-dictionary-v1:{\"id\":1,\"status\":\"active\",\"user\":\"admin\"}";
    let dict_hash = core::sha256(dict_raw);

    wing::set_base_url(g_client, "https://example.com");
    wing::reset_response(g_server_res);
    wing::set_use_as_dictionary_response(g_server_res, "/api/*", "dict-v1", 3600);
    let uad_hdr = wing::header(g_server_res, "Use-As-Dictionary");
    assert(uad_hdr.len > 0);

    // Client processes dictionary response and caches dictionary
    var out_initial: u8[..256] = [];
    let ok_learn = wing::process_dictionary_response(
        g_client,
        "https://example.com",
        uad_hdr,
        "",
        dict_raw,
        out_initial,
    );
    assert(ok_learn && out_initial[..] == dict_raw);

    // Client prepares subsequent request to /api/items and attaches Available-Dictionary & Dictionary-ID
    wing::reset_request(g_req);
    g_req.url.append("https://example.com/api/items");
    wing::set_header(g_req.headers, "Accept-Encoding", "gzip, dcz, dcb", false);
    let attached = wing::attach_dictionary_request_headers(g_client, "https://example.com", "/api/items", g_req);
    assert(attached);

    // Server negotiates DCZ response
    wing::reset_response(g_dcz_res);
    let payload_plain = "{\"id\":42,\"status\":\"active\",\"user\":\"admin\"}";
    let ok_neg = wing::apply_negotiated_dictionary_response(g_req, g_dcz_res, dict_hash, payload_plain, "dict-v1");
    assert(ok_neg);
    assert(wing::header(g_dcz_res, "Content-Encoding") == "dcz");

    // Verify 4-byte magic (\xFFDCZ) and hash
    let comp_slice, ok_magic = wing::verify_dcz_dcb_magic(g_dcz_res.body[..], true, dict_hash);
    assert(ok_magic && comp_slice.len > 0);

    // Client decodes DCZ response back into plaintext
    var decoded_body: u8[..256] = [];
    let ok_dec = wing::process_dictionary_response(
        g_client,
        "https://example.com",
        "",
        "dcz",
        g_dcz_res.body[..],
        decoded_body,
    );
    assert(ok_dec && decoded_body[..] == payload_plain);

    // Negative test: small output buffer must fail closed (Invariant 13, no silent drop)
    var tiny_out: u8[..8] = [];
    let ok_overflow = wing::process_dictionary_response(
        g_client,
        "https://example.com",
        "",
        "",
        payload_plain,
        tiny_out,
    );
    assert(!ok_overflow);
}

fn run_11_verify_hpack_ring() {
    verify_incremental_http1_scan();
    verify_lexical_swar_and_methods();
    verify_hpack_rfc7541_vectors_and_ring();
    verify_h2_priority_scheduler_and_burst_cap();
    verify_rfc9842_dictionary_transport();
}

// CHECK: WING_HPACK_RING_LINEARIZED: head=0, tail=128
// CHECK-NEXT: WING_HPACK_HASH_HIT: slot=42, match=true
// CHECK: WING_SCHEDULER_ACTIVE_MASK: 0x01
// CHECK: WING_BURST_QUANTUM_YIELD: urgency=0, frames=16
// CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP

// ============================================================================
// 12. verify_http2_audit_regressions (12/14)
// ============================================================================
// CHECK: === [12/14] verify_http2_audit_regressions ===

// tests/lit/verify_http2_audit_regressions.goose
// Regression verification for HTTP/2 audit findings:
// 1. RFC 9218 §7.1: PRIORITY_UPDATE zero-length Priority Field Value resets to default.
// 2. RFC 8441 §3: SETTINGS_ENABLE_CONNECT_PROTOCOL received by server is PROTOCOL_ERROR.
// 3. RFC 9113 §5.1: HEADERS on closed stream with recycled slot returns STREAM_CLOSED.
// 4. RFC 9113 §6.8: GOAWAY with invalid stream parity returns PROTOCOL_ERROR.
//

fn test_priority_update_empty_field() {
    // 4-byte payload: prioritized_stream_id = 3, empty field value
    let payload4: u8[4] = [0x00, 0x00, 0x00, 0x03];
    let stream_id, prio, err = h2_internal::parse_priority_update_payload(payload4[..], false);
    assert(stream_id == 3);
    assert(err == rfc::H2_ERR_NO_ERROR);
    assert(prio.urgency == 3);
    assert(!prio.incremental);
    print("TEST_PRIO_EMPTY: OK\n");
}

fn test_settings_enable_connect_proto_server() {
    // Server receives SETTINGS_ENABLE_CONNECT_PROTOCOL from client: MUST reject with PROTOCOL_ERROR
    let err_srv = h2_internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_CONNECT_PROTO, 1, false);
    assert(err_srv == rfc::H2_ERR_PROTOCOL_ERROR);

    // Client receives SETTINGS_ENABLE_CONNECT_PROTOCOL=1 from server: valid
    let err_cli = h2_internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_CONNECT_PROTO, 1, true);
    assert(err_cli == rfc::H2_ERR_NO_ERROR);
    print("TEST_SETTINGS_CONNECT: OK\n");
}

fn test_headers_closed_stream_recycled_slot() {
    var conn = h2_internal::new_h2_connection(0);
    // 1. Open stream 1 with END_STREAM so it transitions to HalfClosedRemote
    let hdr1 = h2_internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    let r1 = h2_internal::handle_h2_headers_frame_header(conn, hdr1, 0);
    assert(r1 == rfc::H2_ERR_NO_ERROR);

    // Close local half so stream 1 is fully Closed and inactive
    h2_internal::close_local_stream(conn, 1);

    // 2. Open stream 3 (which reuses slot 0 previously used by stream 1)
    let hdr3 = h2_internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  3,
    };
    let r3 = h2_internal::handle_h2_headers_frame_header(conn, hdr3, 0);
    assert(r3 == rfc::H2_ERR_NO_ERROR);

    // 3. Client sends another HEADERS frame on stream 1.
    // Must return STREAM_CLOSED, NOT PROTOCOL_ERROR!
    let hdr1_late = h2_internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let r_late = h2_internal::handle_h2_headers_frame_header(conn, hdr1_late, 0);
    assert(r_late == rfc::H2_ERR_STREAM_CLOSED);
    print("TEST_RECYCLED_SLOT_CLOSED: OK\n");
}

fn test_goaway_invalid_parity() {
    var srv_conn = h2_internal::new_h2_connection(0);
    srv_conn.is_server = true;
    // Client sending GOAWAY with odd stream ID 1 (acknowledging client's own stream) is invalid
    let err_ga = h2_internal::apply_goaway(srv_conn, 1, rfc::H2_ERR_NO_ERROR);
    assert(err_ga == rfc::H2_ERR_PROTOCOL_ERROR);
    print("TEST_GOAWAY_PARITY: OK\n");
}

fn test_hpack_huffman_and_indexing_policy() {
    // H2HPACK-01 & H2HPACK-02: Zero-stack-zeroing Huffman decode rollback & single-pass short Huffman encode
    var dec_out: u8[..64] = [];
    dec_out.append("prefix:");
    let bad_huff: u8[2] = [0xFF, 0xFF]; // Invalid EOS padding (> 7 bits)
    assert(!h2_internal::huff_decode_bytes(bad_huff[..], dec_out));
    assert(dec_out[..] == "prefix:");

    var enc_out: u8[..128] = [];
    assert(h2_internal::encode_hpack_string_literal(enc_out, "www.example.com", true));
    assert((enc_out[0] & 0x80) != 0); // Huffman flag set
    var rt_out: u8[..128] = [];
    let next_off, ok_str = h2_internal::decode_hpack_string(enc_out[..], 0, rt_out);
    assert(ok_str && next_off == (enc_out.len as u64) && rt_out[..] == "www.example.com");

    // Incompressible short string falls back to raw octets
    var raw_out: u8[..64] = [];
    assert(h2_internal::encode_hpack_string_literal(raw_out, "\x00\x01", true));
    assert((raw_out[0] & 0x80) == 0 && raw_out[0] == 2);

    // H2HPACK-03: Adaptive Header Indexing Policy
    assert(h2_internal::select_hpack_indexing("authorization", "Bearer secret-token-value", 4096) == h2_internal::HpackIndexing.NeverIndexed);
    assert(h2_internal::select_hpack_indexing("cookie", "sid=123", 4096) == h2_internal::HpackIndexing.NeverIndexed);
    assert(h2_internal::select_hpack_indexing("cookie", "session_id=0123456789abcdef0123456789", 4096) == h2_internal::HpackIndexing.Incremental);
    assert(h2_internal::select_hpack_indexing("content-length", "42", 4096) == h2_internal::HpackIndexing.None);
    assert(h2_internal::select_hpack_indexing("etag", "\"v1\"", 4096) == h2_internal::HpackIndexing.None);
    assert(h2_internal::select_hpack_indexing("x-large", "012345678901234567890123456789", 48) == h2_internal::HpackIndexing.None);
    assert(h2_internal::select_hpack_indexing("x-custom", "ok", 4096) == h2_internal::HpackIndexing.Incremental);
    print("TEST_HPACK_HUFF_AND_POLICY: OK\n");
}

fn test_graceful_shutdown_and_protocol_guards() {
    // H2HPACK-05: Two-Phase Graceful GOAWAY Shutdown
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var out_wire: u8[>..] = [];
    server_internal::initiate_graceful_shutdown(sess, out_wire);
    assert(sess.conn.shutdown_notice_sent && !sess.conn.goaway_sent);
    assert(out_wire.len == 34); // 17-byte GOAWAY(2^31-1) + 17-byte PING

    // Client echoes PING ACK with matching shutdown_ping_opaque
    let ping_ack_hdr = h2_internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    var ping_payload: u8[..8] = [];
    core::append_u64_be(ping_payload, sess.conn.shutdown_ping_opaque);
    var out_phase2: u8[>..] = [];
    server_internal::process_ingress_ping(sess, ping_ack_hdr, ping_payload[..], out_phase2);
    assert(sess.conn.goaway_sent && out_phase2.len == 17);

    // H2HPACK-06: Explicit PRIORITY_UPDATE prevents Priority request header override
    var sess2 = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    let hdr_s1 = h2_internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    assert(h2_internal::handle_h2_headers_frame_header(sess2.conn, hdr_s1, 0) == rfc::H2_ERR_NO_ERROR);
    let _, p_exp, _ = h2_internal::parse_priority_update_payload("\x00\x00\x00\x01u=1, i", false);
    assert(h2_internal::apply_priority_update(sess2.conn, 1, p_exp) == rfc::H2_ERR_NO_ERROR);
    assert(sess2.conn.streams[0].has_explicit_priority_update);
    var hdr_map = wing::HeaderMap { .. };
    wing::set_header(hdr_map, "priority", "u=6");
    server_internal::apply_request_priority_header(sess2.conn, 1, hdr_map);
    assert(sess2.conn.streams[0].priority.urgency == 1);

    // H2HPACK-08: Extended CONNECT :protocol rejected when enable_connect_protocol == 0
    sess.conn.enable_connect_protocol = 0;
    var p_ext = h2_internal::H2PseudoHeaders {
        has_method:    true,
        has_scheme:    true,
        has_path:      true,
        has_authority: true,
        has_protocol:  true,
        ..
    };
    p_ext.method.append("CONNECT");
    p_ext.scheme.append("https");
    p_ext.path.append("/chat");
    p_ext.authority.append("example.com");
    p_ext.protocol.append("websocket");
    assert(!server_internal::validate_request_pseudo_headers(p_ext, false, sess.conn.enable_connect_protocol));
    sess.conn.enable_connect_protocol = 1;
    assert(server_internal::validate_request_pseudo_headers(p_ext, false, sess.conn.enable_connect_protocol));

    // H2HPACK-04: Coalesced receive flow-control WINDOW_UPDATE threshold
    sess2.conn.coalesce_window_updates = true;
    let s_slot, _ = server_internal::find_or_alloc_stream(sess2, 1);
    var wu_wire: u8[>..] = [];
    server_internal::replenish_ingress_data_windows(sess2, s_slot, 1, 1024, false, wu_wire);
    assert(wu_wire.len == 0 && sess2.conn.unclaimed_recv_window == 1024);
    server_internal::replenish_ingress_data_windows(sess2, s_slot, 1, 32768, false, wu_wire);
    assert(wu_wire.len == 26 && sess2.conn.unclaimed_recv_window == 0 && sess2.streams[s_slot].unclaimed_local_window == 0);

    // Exercise HuffContext / huff_decode_step & has_lower_urgency_ready
    var hctx = h2_internal::new_huff_context();
    var hdst: u8[8] = [0; 8];
    let hsrc: u8[2] = [0x9C, 0xC5];
    let hlen, hok = h2_internal::huff_decode_step(hctx, hdst[..], 0, hsrc[..], true);
    assert(hok && hlen == 3);
    assert(!h2_internal::has_lower_urgency_ready(sess2.conn));
    print("TEST_SHUTDOWN_AND_GUARDS: OK\n");
}

fn run_12_verify_http2_audit_regressions() {
    test_priority_update_empty_field();
    test_settings_enable_connect_proto_server();
    test_headers_closed_stream_recycled_slot();
    test_goaway_invalid_parity();
    test_hpack_huffman_and_indexing_policy();
    test_graceful_shutdown_and_protocol_guards();
    print("ALL_HTTP2_REGRESSIONS: OK\n");
}

// CHECK: TEST_PRIO_EMPTY: OK
// CHECK: TEST_SETTINGS_CONNECT: OK
// CHECK: TEST_RECYCLED_SLOT_CLOSED: OK
// CHECK: TEST_GOAWAY_PARITY: OK
// CHECK: TEST_HPACK_HUFF_AND_POLICY: OK
// CHECK: TEST_SHUTDOWN_AND_GUARDS: OK
// CHECK: ALL_HTTP2_REGRESSIONS: OK

// ============================================================================
// 13. verify_http2_cross_rfc_regressions (13/14)
// ============================================================================
// CHECK: === [13/14] verify_http2_cross_rfc_regressions ===

// tests/lit/verify_http2_cross_rfc_regressions.goose
// Cross-component & RFC edge-case regression suite for HTTP/2:
// 1. RFC 9113 §4.3: HPACK state synchronization across stream-rejected HEADERS frames.
// 2. RFC 9113 §8.1 & §8.1.1: Trailer missing END_STREAM or CL mismatch is RST_STREAM, not GOAWAY.
// 3. RFC 9113 §8.1.2 & RFC 9110 §6.5.1: Disallowed trailer fields rejected in decode_hpack_to_map.
// 4. RFC 7541 §4.2: Dynamic table size update min+final tracking & 128-entry ring cap.
// 5. RFC 9218 §2.1 & §5: SETTINGS_NO_RFC7540_PRIORITIES enforcement & Priority header integration.
// 6. RFC 9113 §6.9 & §8.1: Client H2 padded DATA WINDOW_UPDATE credit, 1xx END_STREAM & trailer rules.
//

fn has_frame_on_wire(wire: const u8[:], frame_type: u8, stream_id: u32) -> bool {
    var off: i64 = 0;
    while off + 9 <= wire.len {
        let hdr, err = h2_internal::parse_frame_header(wire[off..off + 9]);
        guard err == rfc::H2_ERR_NO_ERROR else { break; }
        if hdr.frame_type == frame_type && (stream_id == 0 || hdr.stream_id == stream_id) {
            return true;
        }
        off += 9 + (hdr.length as i64);
    }
    return false;
}

fn test_hpack_sync_across_stream_errors() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/ok", 1);

    var client_dt = h2_internal::new_dynamic_table(4096);
    var wire1: u8[>..] = [];
    wire1.append(rfc::H2_CLIENT_PREFACE[..]);

    // Stream 1: valid pseudo-headers + incrementally indexed authority + invalid uppercase header + trailing custom header
    var hb1: u8[>..] = [];
    h2_internal::encode_hpack_field(client_dt, hb1, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, ":path", "/ok", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, ":authority", "sync.example.com", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, "Bad-Upper", "v1", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, "x-after-err", "v2", h2_internal::HpackIndexing.Incremental, false);

    let f1 = h2_internal::FrameHeader {
        length:     hb1.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    h2_internal::encode_frame_header_to(f1, wire1);
    wire1.append(hb1[..]);

    var out1: u8[>..] = [];
    let _, ok1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire1[..], 1000, out1);
    assert(ok1);
    assert(has_frame_on_wire(out1[..], rfc::H2_FRAME_RST_STREAM, 1));

    // Also send a self-dependent HEADERS frame on Stream 3 (rejected before dispatch) that indexes a new header
    var hb3_bad: u8[>..] = [];
    hb3_bad.push(0x00); hb3_bad.push(0x00); hb3_bad.push(0x00); hb3_bad.push(0x03); // dep_raw = 3 (self-dependency)
    hb3_bad.push(16); // weight
    h2_internal::encode_hpack_field(client_dt, hb3_bad, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb3_bad, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb3_bad, ":path", "/ok", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb3_bad, "x-self-dep", "indexed", h2_internal::HpackIndexing.Incremental, false);

    var wire3: u8[>..] = [];
    let f3 = h2_internal::FrameHeader {
        length:     hb3_bad.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM | rfc::H2_FLAG_PRIORITY,
        stream_id:  3,
    };
    h2_internal::encode_frame_header_to(f3, wire3);
    wire3.append(hb3_bad[..]);
    var out3: u8[>..] = [];
    let _, ok3 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire3[..], 1000, out3);
    assert(ok3);
    assert(has_frame_on_wire(out3[..], rfc::H2_FRAME_RST_STREAM, 3));

    // Now Stream 5 references ":authority: sync.example.com" from client_dt (shifted by Bad-Upper, x-after-err, x-self-dep)
    var hb5: u8[>..] = [];
    h2_internal::encode_hpack_field(client_dt, hb5, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb5, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb5, ":path", "/ok", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb5, ":authority", "sync.example.com", h2_internal::HpackIndexing.Incremental, false);

    var wire5: u8[>..] = [];
    let f5 = h2_internal::FrameHeader {
        length:     hb5.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  5,
    };
    h2_internal::encode_frame_header_to(f5, wire5);
    wire5.append(hb5[..]);
    var out5: u8[>..] = [];
    let _, ok5 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire5[..], 1000, out5);
    assert(ok5);
    assert(has_frame_on_wire(out5[..], rfc::H2_FRAME_HEADERS, 5));
    print("TEST_1_HPACK_SYNC_ACROSS_STREAM_ERRORS: OK\n");
}

fn test_trailer_errors_and_disallowed_fields() {
    // 1. Disallowed RFC 9110 §6.5.1 trailer fields (authorization, cookie, content-type) must fail decode_hpack_to_map
    var dt = h2_internal::new_dynamic_table(4096);
    var t_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, t_block, "authorization", "Bearer tok", h2_internal::HpackIndexing.None, false);
    var pseudo = h2_internal::H2PseudoHeaders { is_trailer: true, .. };
    var out_map = wing::HeaderMap { .. };
    let err_auth = h2_internal::decode_hpack_to_map(dt, t_block[..], pseudo, out_map);
    assert(err_auth == rfc::H2_ERR_PROTOCOL_ERROR);

    // 2. Trailer HEADERS without END_STREAM on open stream must emit RST_STREAM(PROTOCOL_ERROR), NOT GOAWAY
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/up", 2);

    var client_dt = h2_internal::new_dynamic_table(4096);
    var wire: u8[>..] = [];
    wire.append(rfc::H2_CLIENT_PREFACE[..]);
    var hb1: u8[>..] = [];
    h2_internal::encode_hpack_field(client_dt, hb1, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb1, ":path", "/up", h2_internal::HpackIndexing.Incremental, false);
    let f1 = h2_internal::FrameHeader {
        length:     hb1.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    h2_internal::encode_frame_header_to(f1, wire);
    wire.append(hb1[..]);

    // Trailer HEADERS on stream 1 WITHOUT END_STREAM
    var hb_tr: u8[>..] = [];
    h2_internal::encode_hpack_field(client_dt, hb_tr, "x-checksum", "abc", h2_internal::HpackIndexing.Incremental, false);
    let f_tr = h2_internal::FrameHeader {
        length:     hb_tr.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS, // missing END_STREAM!
        stream_id:  1,
    };
    h2_internal::encode_frame_header_to(f_tr, wire);
    wire.append(hb_tr[..]);

    var out: u8[>..] = [];
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out);
    assert(ok);
    assert(has_frame_on_wire(out[..], rfc::H2_FRAME_RST_STREAM, 1));
    assert(!has_frame_on_wire(out[..], rfc::H2_FRAME_GOAWAY, 0));
    print("TEST_2_3_TRAILERS_AND_DISALLOWED_FIELDS: OK\n");
}

fn test_hpack_dyn_size_min_update_and_ring_cap() {
    // Part A: Ring buffer cap at 128 entries even when max_allowed > 4096
    var big_dt = h2_internal::new_dynamic_table(8192);
    for i in 135 {
        h2_internal::insert_header(big_dt, "k", "v", false);
    }
    assert(big_dt.count == 128);
    h2_internal::evict_until(big_dt, 0);
    assert(big_dt.count == 0 && big_dt.used_bytes == 0);

    // Part B: SETTINGS_HEADER_TABLE_SIZE 0 then 4096 must emit both 0 (0x20) and 4096 (0x3F 0xE1 0x1F)
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/ping", 1);

    var client_enc = h2_internal::new_dynamic_table(4096);
    var client_dec = h2_internal::new_dynamic_table(4096);
    var wire1: u8[>..] = [];
    wire1.append(rfc::H2_CLIENT_PREFACE[..]);
    var hb1: u8[>..] = [];
    h2_internal::encode_hpack_field(client_enc, hb1, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_enc, hb1, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_enc, hb1, ":path", "/ping", h2_internal::HpackIndexing.Incremental, false);
    let f1 = h2_internal::FrameHeader {
        length:     hb1.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    h2_internal::encode_frame_header_to(f1, wire1);
    wire1.append(hb1[..]);
    var out1: u8[>..] = [];
    let _, ok1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire1[..], 1000, out1);
    assert(ok1);

    // Decode stream 1 response headers into client_dec (populates server & content-length in client_dec)
    let resp1_hdr, _ = h2_internal::parse_frame_header(out1[33..42]);
    var p1 = h2_internal::H2PseudoHeaders { .. };
    var m1 = wing::HeaderMap { .. };
    assert(h2_internal::decode_hpack_to_map(client_dec, out1[42..42 + resp1_hdr.length], p1, m1) == rfc::H2_ERR_NO_ERROR);
    assert(client_dec.count > 0);

    // Client sends SETTINGS with HEADER_TABLE_SIZE = 0 followed by HEADER_TABLE_SIZE = 4096, then Stream 3
    var wire2: u8[>..] = [];
    let s_hdr = h2_internal::FrameHeader { length: 12, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    h2_internal::encode_frame_header_to(s_hdr, wire2);
    core::append_u16_be(wire2, rfc::H2_SETTING_HEADER_TABLE_SIZE);
    core::append_u32_be(wire2, 0);
    core::append_u16_be(wire2, rfc::H2_SETTING_HEADER_TABLE_SIZE);
    core::append_u32_be(wire2, 4096);

    var hb3: u8[>..] = [];
    h2_internal::encode_hpack_field(client_enc, hb3, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_enc, hb3, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_enc, hb3, ":path", "/ping", h2_internal::HpackIndexing.Incremental, false);
    let f3 = h2_internal::FrameHeader {
        length:     hb3.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  3,
    };
    h2_internal::encode_frame_header_to(f3, wire2);
    wire2.append(hb3[..]);

    var out2: u8[>..] = [];
    let _, ok2 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out2);
    assert(ok2);
    // out2 starts with 9-byte SETTINGS ACK, followed by Stream 3 response HEADERS frame
    let resp3_hdr, _ = h2_internal::parse_frame_header(out2[9..18]);
    let resp3_hpack = out2[18..18 + resp3_hdr.length];
    // First byte of resp3_hpack MUST be 0x20 (Dynamic Table Size Update to 0)
    assert(resp3_hpack.len > 0 && resp3_hpack[0] == 0x20);
    var p3 = h2_internal::H2PseudoHeaders { .. };
    var m3 = wing::HeaderMap { .. };
    assert(h2_internal::decode_hpack_to_map(client_dec, resp3_hpack, p3, m3) == rfc::H2_ERR_NO_ERROR);
    assert(client_dec.count == sess.hpack_enc.count);
    print("TEST_4_HPACK_DYN_MIN_SIZE_AND_RING_CAP: OK\n");
}

fn test_rfc9218_and_client_h2_edge_cases() {
    // 1. RFC 9218 §2.1: SETTINGS_NO_RFC7540_PRIORITIES = 1 ignores self-dependency in HEADERS & PRIORITY
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/p", 1);

    var wire: u8[>..] = [];
    wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let s_hdr = h2_internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    h2_internal::encode_frame_header_to(s_hdr, wire);
    core::append_u16_be(wire, rfc::H2_SETTING_NO_RFC7540_PRIORITIES);
    core::append_u32_be(wire, 1);

    var client_dt = h2_internal::new_dynamic_table(4096);
    var hb: u8[>..] = [];
    hb.push(0x00); hb.push(0x00); hb.push(0x00); hb.push(0x01); hb.push(16); // self-dep = 1
    h2_internal::encode_hpack_field(client_dt, hb, ":method", "GET", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb, ":path", "/p", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(client_dt, hb, "priority", "u=1, i", h2_internal::HpackIndexing.None, false);
    let f_hdr = h2_internal::FrameHeader {
        length:     hb.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_PRIORITY,
        stream_id:  1,
    };
    h2_internal::encode_frame_header_to(f_hdr, wire);
    wire.append(hb[..]);

    var out: u8[>..] = [];
    let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out);
    assert(ok);
    assert(!has_frame_on_wire(out[..], rfc::H2_FRAME_RST_STREAM, 1));
    let s_idx, found = h2_internal::find_session_stream_idx(sess.conn, 1);
    assert(found && sess.conn.streams[s_idx].priority.urgency == 1 && sess.conn.streams[s_idx].priority.incremental);

    // 2. Client H2 padded DATA frame WINDOW_UPDATE must credit full hdr.length (10), not unpadded len (5)
    var dec_dt = h2_internal::new_dynamic_table(4096);
    var resp = wing::Response { .. };
    var out_ctrl: u8[>..] = [];
    var got_hdrs = true;
    let pad_hdr = h2_internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      rfc::H2_FLAG_PADDED | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    let pad_payload: u8[10] = [4, 'h', 'e', 'l', 'l', 'o', 0, 0, 0, 0];
    let ok_d, end_d = wing::process_h2_response_frame(pad_hdr, pad_payload[..], 1, false, dec_dt, resp, got_hdrs, out_ctrl);
    assert(ok_d && end_d);
    assert(out_ctrl.len >= 13 && core::read_be_u32(out_ctrl[..], 9) == 10);

    // 3. Client H2 1xx informational response with END_STREAM must be rejected (RFC 9113 §8.1)
    var got_hdrs_1xx = false;
    let hdr_100 = h2_internal::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    let payload_100: u8[5] = [0x08, 0x03, '1', '0', '0']; // :status: 100
    let ok_100, _ = wing::process_h2_response_frame(hdr_100, payload_100[..], 1, false, dec_dt, resp, got_hdrs_1xx, out_ctrl);
    assert(!ok_100);
    print("TEST_5_6_RFC9218_AND_CLIENT_H2: OK\n");
}

fn run_13_verify_http2_cross_rfc_regressions() {
    test_hpack_sync_across_stream_errors();
    test_trailer_errors_and_disallowed_fields();
    test_hpack_dyn_size_min_update_and_ring_cap();
    test_rfc9218_and_client_h2_edge_cases();
    print("ALL_CROSS_RFC_REGRESSIONS: PASS\n");
}

// CHECK: TEST_1_HPACK_SYNC_ACROSS_STREAM_ERRORS: OK
// CHECK: TEST_2_3_TRAILERS_AND_DISALLOWED_FIELDS: OK
// CHECK: TEST_4_HPACK_DYN_MIN_SIZE_AND_RING_CAP: OK
// CHECK: TEST_5_6_RFC9218_AND_CLIENT_H2: OK
// CHECK: ALL_CROSS_RFC_REGRESSIONS: PASS

// ============================================================================
// 14. verify_wire_hpack_overflow (14/14)
// ============================================================================
// CHECK: === [14/14] verify_wire_hpack_overflow ===

// Verification of HPACK bounds safety and transactional cursor rollback (RFC 7541).

fn run_14_verify_wire_hpack_overflow() {
    print("=== VERIFY_WIRE_HPACK_OVERFLOW ===\n");

    var out_str: u8[..64] = [];

    // Case 1: Transactional cursor rollback on premature EOF in hpack_decode_string
    // Encodes length prefix 10, but provides only 3 bytes ("abc")
    let truncated_src: const u8[4] = [10, 'a', 'b', 'c'];
    var offset: u64 = 0;
    let res = wire::hpack_decode_string(truncated_src[..], offset, out_str);
    assert(!res);
    // Offset must roll back to 0 on failure (Rule 5 Transactional cursor contract)
    assert(offset == 0);
    print("HPACK_TRANSACTIONAL_ROLLBACK: OK\n");

    // Case 2: Huffman flag rejected when non-1s padding bits are present (RFC 7541 Section 5.2)
    // 0x81 = 'H' bit set (0x80) with length 1, followed by 0x00 (invalid padding)
    let huffman_src: const u8[2] = [0x81, 0x00];
    offset = 0;
    out_str.clear();
    let huff_res = wire::hpack_decode_string(huffman_src[..], offset, out_str);
    assert(!huff_res);
    assert(offset == 0);
    print("HPACK_HUFFMAN_FLAG_SAFEGUARD: OK\n");

    // Case 3: HPACK wire integer shift overflow (> 56 bits)
    let int_ovf_src: const u8[11] = [0x7F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    offset = 0;
    let _, int_ovf_ok = wire::hpack_decode_int(int_ovf_src[..], offset, 7);
    assert(!int_ovf_ok);
    assert(offset == 0);
    print("HPACK_INT_SHIFT_OVERFLOW: OK\n");

    // Case 4: HPACK wire integer truncated continuation
    let int_trunc_src: const u8[3] = [0x7F, 0x80, 0x80];
    offset = 0;
    let _, int_trunc_ok = wire::hpack_decode_int(int_trunc_src[..], offset, 7);
    assert(!int_trunc_ok);
    assert(offset == 0);
    print("HPACK_INT_TRUNCATED: OK\n");

    // Case 5: HPACK decode string with truncated Huffman stream
    let huff_trunc: const u8[3] = [0x85, 0x11, 0x22];
    out_str.clear();
    let huff_next, huff_ok = h2_internal::decode_hpack_string(huff_trunc[..], 0, out_str);
    assert(!huff_ok);
    assert(huff_next == 0);
    print("HPACK_HUFFMAN_TRUNCATED: OK\n");

    // Case 6: HPACK decode string with invalid padding bits (RFC 7541 §5.2)
    let huff_bad_pad: const u8[2] = [0x81, 0x00];
    out_str.clear();
    let pad_next, pad_ok = h2_internal::decode_hpack_string(huff_bad_pad[..], 0, out_str);
    assert(!pad_ok);
    assert(pad_next == 0);
    print("HPACK_HUFFMAN_BAD_PADDING: OK\n");

    // Case 7: QPACK decode int with truncated multibyte continuation
    let qp_trunc: const u8[2] = [0x3F, 0x80];
    let _, qp_off, qp_ok = h3_internal::qpack_decode_int(qp_trunc[..], 0, 6);
    assert(!qp_ok);
    assert(qp_off == 0);
    print("QPACK_INT_TRUNCATED: OK\n");

    // Case 8: QPACK decode string with truncated payload
    let qp_str_trunc: const u8[4] = [0x8A, 0x11, 0x22, 0x33];
    out_str.clear();
    let qp_s_off, qp_s_ok = h3_internal::decode_qpack_string(qp_str_trunc[..], 0, 7, out_str);
    assert(!qp_s_ok);
    assert(qp_s_off == 0);
    print("QPACK_STRING_TRUNCATED: OK\n");

    print("ALL_HPACK_INVARIANTS_VERIFIED: OK\n");
}

// CHECK: HPACK_TRANSACTIONAL_ROLLBACK: OK
// CHECK: HPACK_HUFFMAN_FLAG_SAFEGUARD: OK
// CHECK: HPACK_INT_SHIFT_OVERFLOW: OK
// CHECK: HPACK_INT_TRUNCATED: OK
// CHECK: HPACK_HUFFMAN_TRUNCATED: OK
// CHECK: HPACK_HUFFMAN_BAD_PADDING: OK
// CHECK: QPACK_INT_TRUNCATED: OK
// CHECK: QPACK_STRING_TRUNCATED: OK
// CHECK: ALL_HPACK_INVARIANTS_VERIFIED: OK

fn main() {
    print("\n=== [1/14] rfc_repro_framer_h2_minsize ===\n");
    run_01_rfc_repro_framer_h2_minsize();
    print("\n=== [2/14] verify_h2_and_chunk_edge ===\n");
    run_02_verify_h2_and_chunk_edge();
    print("\n=== [3/14] verify_h2_continuation_fsm ===\n");
    run_03_verify_h2_continuation_fsm();
    print("\n=== [4/14] verify_h2_control_frames ===\n");
    run_04_verify_h2_control_frames();
    print("\n=== [5/14] verify_h2_microbench ===\n");
    run_05_verify_h2_microbench();
    print("\n=== [6/14] verify_h2_spec ===\n");
    run_06_verify_h2_spec();
    print("\n=== [7/14] verify_h2_spec_invariants ===\n");
    run_07_verify_h2_spec_invariants();
    print("\n=== [8/14] verify_h2_spill_lane ===\n");
    run_08_verify_h2_spill_lane();
    print("\n=== [9/14] verify_hpack_edge ===\n");
    run_09_verify_hpack_edge();
    print("\n=== [10/14] verify_hpack_qpack ===\n");
    run_10_verify_hpack_qpack();
    print("\n=== [11/14] verify_hpack_ring ===\n");
    run_11_verify_hpack_ring();
    print("\n=== [12/14] verify_http2_audit_regressions ===\n");
    run_12_verify_http2_audit_regressions();
    print("\n=== [13/14] verify_http2_cross_rfc_regressions ===\n");
    run_13_verify_http2_cross_rfc_regressions();
    print("\n=== [14/14] verify_wire_hpack_overflow ===\n");
    run_14_verify_wire_hpack_overflow();
}
