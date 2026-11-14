// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP/2 Protocol, Multiplexing, HPACK, and RFC Invariants Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: http2_suite ---
// HTTP/2 Echelon 6 Conformance & Reference Suite (RFC 7541, RFC 9113, RFC 9218).
// Tests HPACK Huffman FSM, Zero-Allocation Dynamic Table, Binary Framing,
// Two-Level Signed Flow Control, RFC 9218 Write Scheduler, and Anti-DoS Defenses.

// 1. HPACK Huffman FSM & RFC 7541 Integer Codec Tests
fn test_hpack_huffman_and_integer_codec(t: lit::T&) {
    t.run("HPACK-01: RFC 7541 Appendix C.2 Huffman Decode Vectors") { sub =>
        // Vector 1: "www.example.com"
        let enc_www: u8[12] = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        var dec_www: u8[..64] = [];
        let ok_www = internal::decode_huffman_exact(enc_www[..], dec_www);
        sub.assert_true(ok_www, "decode www.example.com succeeds");
        sub.assert_eq(dec_www[..], "www.example.com", "decoded string matches RFC 7541 vector");

        // Vector 2: "no-cache"
        let enc_nc: u8[6] = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        var dec_nc: u8[..64] = [];
        let ok_nc = internal::decode_huffman_exact(enc_nc[..], dec_nc);
        sub.assert_true(ok_nc, "decode no-cache succeeds");
        sub.assert_eq(dec_nc[..], "no-cache", "decoded string matches RFC 7541 vector");

        // Vector 3: "custom-key" (RFC 7541 Appendix C.2.3)
        let enc_ck: u8[8] = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        var dec_ck: u8[..64] = [];
        let ok_ck = internal::decode_huffman_exact(enc_ck[..], dec_ck);
        sub.assert_true(ok_ck, "decode custom-key succeeds");
        sub.assert_eq(dec_ck[..], "custom-key", "decoded string matches RFC 7541 vector");

        // Vector 4: "custom-value"
        let enc_cv: u8[9] = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
        var dec_cv: u8[..64] = [];
        let ok_cv = internal::decode_huffman_exact(enc_cv[..], dec_cv);
        sub.assert_true(ok_cv, "decode custom-value succeeds");
        sub.assert_eq(dec_cv[..], "custom-value", "decoded string matches RFC 7541 vector");
    };

    t.run("HPACK-02: Huffman Encode / Decode Roundtrip") { sub =>
        let test_str: const u8[:] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        var encoded: u8[..128] = [];
        internal::huff_encode_bytes(test_str, encoded);
        sub.assert_true(encoded.len > 0, "encoded length > 0");
        sub.assert_true(encoded.len < test_str.len, "huffman achieves compression");

        var decoded: u8[..128] = [];
        let ok_round = internal::decode_huffman_exact(encoded[..], decoded);
        sub.assert_true(ok_round, "roundtrip decode succeeds");
        sub.assert_eq(decoded[..], test_str, "decoded matches original string");
    };

    t.run("HPACK-03: Invalid Huffman Padding & EOS Rejection (RFC 7541 Section 5.2)") { sub =>
        // Padding bits must strictly be 1s (EOS prefix). Zero bits in padding must fail.
        // "www.example.com" ending with 0x00 instead of 0xff padding
        let bad_pad: u8[12] = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0x00,
        ];
        var out_bad: u8[..64] = [];
        let ok_bad = internal::decode_huffman_exact(bad_pad[..], out_bad);
        sub.assert_false(ok_bad, "non-1s padding bits must be rejected");

        // Padding strictly longer than 7 bits must fail.
        let overlong_pad: u8[3] = [0xff, 0xff, 0xff];
        var out_over: u8[..64] = [];
        let ok_over = internal::decode_huffman_exact(overlong_pad[..], out_over);
        sub.assert_false(ok_over, "overlong padding > 7 bits must be rejected");
    };

    t.run("HPACK-04: Integer Shift Overflow Guard (Trail of Bits FIND-401 / CVE-2022-41723)") { sub =>
        // 5-bit prefix with excessive continuation bytes (shift >= 28)
        let malformed_int: u8[8] = [
            0x1F, // 5 bits all 1s
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00,
        ];
        let val, next_off, ok = internal::hpack_decode_int(malformed_int[..], 0, 5);
        sub.assert_false(ok, "integer exceeding 28 bits shift must fail cleanly without integer overflow");
    };

    t.run("HPACK-05: Integer Codec Multi-Prefix Roundtrip") { sub =>
        // Fits in prefix: 10 with 5-bit prefix
        var buf: u8[..32] = [];
        internal::hpack_encode_int(buf, 10, 5, 0x20);
        let val1, off1, ok1 = internal::hpack_decode_int(buf[..], 0, 5);
        sub.assert_true(ok1, "single byte int decode succeeds");
        sub.assert_eq(val1, 10, "value 10 matches");

        // Multi-byte int: 1337 with 6-bit prefix
        buf.clear();
        internal::hpack_encode_int(buf, 1337, 6, 0x40);
        let val2, off2, ok2 = internal::hpack_decode_int(buf[..], 0, 6);
        sub.assert_true(ok2, "multi-byte int decode succeeds");
        sub.assert_eq(val2, 1337, "value 1337 matches");
    };
}

// 2. HPACK Dynamic Table & Header Block Conformance Tests
fn test_hpack_dynamic_table_and_header_blocks(t: lit::T&) {
    t.run("DYN-01: Insertion, LIFO Indexing & FIFO Eviction") { sub =>
        var dt = internal::new_dynamic_table(256); // small capacity for quick eviction

        // Insert first entry (32 overhead + 6 + 1 = 39 bytes)
        internal::insert_header(dt, "custom", "1");
        sub.assert_eq(dt.count, 1, "count is 1");
        sub.assert_eq(dt.used_bytes, 39, "used_bytes is 39");

        // Dynamic table index 62 must point to custom:1
        var n1: u8[..32] = [];
        var v1: u8[..32] = [];
        let ok_g1 = internal::get_indexed_header(dt, 62, n1, v1);
        sub.assert_true(ok_g1, "get index 62");
        sub.assert_eq(n1[..], "custom", "name matches");
        sub.assert_eq(v1[..], "1", "val matches");

        // Insert second entry (32 overhead + 6 + 1 = 39 bytes -> total 78 bytes)
        internal::insert_header(dt, "custom", "2");
        sub.assert_eq(dt.count, 2, "count is 2");
        sub.assert_eq(dt.used_bytes, 78, "used_bytes is 78");

        // LIFO external indexing: index 62 is "custom:2", index 63 is "custom:1"
        var n2: u8[..32] = [];
        var v2: u8[..32] = [];
        internal::get_indexed_header(dt, 62, n2, v2);
        sub.assert_eq(v2[..], "2", "index 62 is newest entry");

        var n3: u8[..32] = [];
        var v3: u8[..32] = [];
        internal::get_indexed_header(dt, 63, n3, v3);
        sub.assert_eq(v3[..], "1", "index 63 is older entry");
    };

    t.run("DYN-02: Zero-Allocation In-Place Compaction Invariant") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Force insertions that push arena_write_pos near 4096
        var i: u32 = 0;
        while i < 60 {
            internal::insert_header(dt, "x-header-key", "some-fixed-value-to-consume-arena-bytes");
            i++;
        }
        sub.assert_true(dt.count > 0, "entries successfully inserted");
        // Verify lookup still returns valid headers after arena usage
        var name_buf: u8[..32] = [];
        var val_buf:  u8[..64] = [];
        let ok = internal::get_indexed_header(dt, 62, name_buf, val_buf);
        sub.assert_true(ok, "lookup after high-volume insertion succeeds");
        sub.assert_eq(name_buf[..], "x-header-key", "header name intact");
    };

    t.run("DYN-03: Header Block Decode with Pseudo-Headers (RFC 9113 Section 8.3)") { sub =>
        var dt = internal::new_dynamic_table(4096);

        // Encode block:
        // 1. Indexed :method: GET (static index 2 -> 0x82)
        // 2. Indexed :scheme: https (static index 7 -> 0x87)
        // 3. Indexed :path: / (static index 4 -> 0x84)
        let raw_block: u8[3] = [0x82, 0x87, 0x84];
        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, raw_block[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "valid pseudo-headers decode with NO_ERROR");
        sub.assert_true(pseudo.has_method && pseudo.has_scheme && pseudo.has_path, "3 pseudo-fields decoded");
        sub.assert_eq(pseudo.method[..], "GET", "GET value");
    };

    t.run("DYN-04: Pseudo-Header Ordering Violation Rejection (RFC 9113 Section 8.3)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Block:
        // 1. Regular header: accept: */* (static index 19 -> 0x93)
        // 2. Pseudo header: :path: / (static index 4 -> 0x84)  <-- ILLEGAL: pseudo after regular!
        let raw_block: u8[2] = [0x93, 0x84];
        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, raw_block[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "pseudo-header after regular header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-05: Duplicate Pseudo-Header Rejection") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Block: duplicate :method: GET (0x82, 0x82)
        let raw_block: u8[2] = [0x82, 0x82];
        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, raw_block[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "duplicate pseudo-header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-06: Content-Length Consistency & Smuggling Guard (CVE-2026-78660)") { sub =>
        var dt = internal::new_dynamic_table(4096);

        // Block with mismatching Content-Length:
        // 1. :method: POST (0x83)
        // 2. Literal "content-length": "10"
        // 3. Literal "content-length": "20"
        var raw_block: u8[..64] = [];
        raw_block.push(0x83); // :method: POST

        // Literal without indexing: 0x00, name "content-length" (len 14), val "10" (len 2)
        raw_block.push(0x00);
        raw_block.push(14);
        raw_block.append("content-length");
        raw_block.push(2);
        raw_block.append("10");

        // Second literal "content-length": "20"
        raw_block.push(0x00);
        raw_block.push(14);
        raw_block.append("content-length");
        raw_block.push(2);
        raw_block.append("20");

        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, raw_block[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "conflicting Content-Length headers must trigger PROTOCOL_ERROR");

        // Identical matching Content-Length: "10" and "10" must be accepted
        raw_block.clear();
        raw_block.push(0x83); // :method: POST
        raw_block.push(0x87); // :scheme: https
        raw_block.push(0x84); // :path: /
        raw_block.push(0x00); raw_block.push(14); raw_block.append("content-length"); raw_block.push(2); raw_block.append("10");
        raw_block.push(0x00); raw_block.push(14); raw_block.append("content-length"); raw_block.push(2); raw_block.append("10");

        var pseudo_ok = internal::H2PseudoHeaders { .. };
        var out_ok = wing::HeaderMap { .. };
        let err_ok = internal::decode_hpack_to_map(dt, raw_block[..], pseudo_ok, out_ok);
        sub.assert_eq(err_ok, rfc::H2_ERR_NO_ERROR, "identical multiple Content-Length headers are accepted");
    };

    t.run("DYN-07: Forbidden Connection Headers Rejection (RFC 9113 Section 8.2.2)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Literal header "connection": "close"
        var raw_block: u8[..32] = [];
        raw_block.push(0x00);
        raw_block.push(10);
        raw_block.append("connection");
        raw_block.push(5);
        raw_block.append("close");

        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, raw_block[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "forbidden 'connection' header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-08: Missing Mandatory Pseudo-Headers Rejection (RFC 9113 §8.3.1)") { sub =>
        var dt = internal::new_dynamic_table(4096);

        // Missing :path (only :method: GET and :scheme: https)
        let block_no_path: u8[2] = [0x82, 0x87];
        var pseudo1 = internal::H2PseudoHeaders { .. };
        var out1 = wing::HeaderMap { .. };
        let err1 = internal::decode_hpack_to_map(dt, block_no_path[..], pseudo1, out1);
        sub.assert_eq(err1, rfc::H2_ERR_PROTOCOL_ERROR, "request without :path must trigger PROTOCOL_ERROR");

        // Missing all pseudo-headers (only regular header)
        var block_no_pseudo: u8[..32] = [];
        block_no_pseudo.push(0x00);
        block_no_pseudo.push(10);
        block_no_pseudo.append("user-agent");
        block_no_pseudo.push(3);
        block_no_pseudo.append("bot");
        var pseudo2 = internal::H2PseudoHeaders { .. };
        var out2 = wing::HeaderMap { .. };
        let err2 = internal::decode_hpack_to_map(dt, block_no_pseudo[..], pseudo2, out2);
        sub.assert_eq(err2, rfc::H2_ERR_PROTOCOL_ERROR, "request without pseudo-headers must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-09: Header Field Name Character Validation (RFC 9113 §8.2.1)") { sub =>
        // Disallowed non-tchar characters: '(', ';', '=', uppercase
        sub.assert_false(internal::validate_h2_field_syntax("user(agent)", "test"), "parenthesis disallowed in name");
        sub.assert_false(internal::validate_h2_field_syntax("bad;name", "test"), "semicolon disallowed in name");
        sub.assert_false(internal::validate_h2_field_syntax("key=val", "test"), "equals disallowed in name");
        sub.assert_false(internal::validate_h2_field_syntax("User-Agent", "test"), "uppercase disallowed in name");
        sub.assert_true(internal::validate_h2_field_syntax("user-agent", "test"), "lowercase tchar valid");
        sub.assert_true(internal::validate_h2_field_syntax(":method", "GET"), "pseudo-header valid");
    };
}

// 3. Binary Framing & RFC 9218 Structured Field Prioritization Tests
fn test_binary_framing_and_rfc9218(t: lit::T&) {
    t.run("FRAME-01: 9-Byte Frame Header Codec Roundtrip") { sub =>
        let orig_hdr = internal::FrameHeader {
            length:     16384,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_END_STREAM,
            stream_id:  101,
        };

        var buf: u8[9] = [0; 9];
        internal::encode_frame_header(orig_hdr, buf);
        sub.assert_eq(buf.len, 9, "frame header is exactly 9 bytes");

        let parsed_hdr, err = internal::parse_frame_header(buf[..]);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "parse_frame_header succeeds");
        sub.assert_eq(parsed_hdr.length, 16384, "payload length matches");
        sub.assert_eq(parsed_hdr.frame_type, rfc::H2_FRAME_DATA, "frame type matches");
        sub.assert_eq(parsed_hdr.flags, rfc::H2_FLAG_END_STREAM, "flags match");
        sub.assert_eq(parsed_hdr.stream_id, 101, "stream id matches");
    };

    t.run("FRAME-02: PADDED Payload Extraction") { sub =>
        let hdr = internal::FrameHeader {
            length:     12,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_PADDED,
            stream_id:  1,
        };
        // Payload: 1 byte pad length (3), 8 bytes data, 3 bytes padding
        let payload: u8[12] = [
            0x03,                                           // Pad length: 3
            'h', 'e', 'l', 'l', 'o', '!', '!', '!',         // 8 bytes data
            0x00, 0x00, 0x00,                               // 3 bytes padding
        ];

        let unpadded, err = internal::extract_padded_frame_payload(hdr, payload[..]);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "extract padding succeeds");
        sub.assert_eq(unpadded.len, 8, "unpadded length is 8");
        sub.assert_eq(unpadded, "hello!!!", "unpadded data intact");

        // Invalid padding length: pad_len (15) > length (12) -> PROTOCOL_ERROR
        let bad_payload: u8[12] = [0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let _, bad_err = internal::extract_padded_frame_payload(hdr, bad_payload[..]);
        sub.assert_eq(bad_err, rfc::H2_ERR_PROTOCOL_ERROR, "oversized padding triggers PROTOCOL_ERROR");
    };

    t.run("FRAME-03: RFC 9218 Priority Dictionary Parser") { sub =>
        // Vector 1: "u=0, i"
        let p1, ok1 = wing::parse_http_priority("u=0, i");
        sub.assert_true(ok1, "parse u=0, i succeeds");
        sub.assert_eq(p1.urgency, 0, "urgency is 0");
        sub.assert_true(p1.incremental, "incremental is true");

        // Vector 2: "u=5"
        let p2, ok2 = wing::parse_http_priority("u=5");
        sub.assert_true(ok2, "parse u=5 succeeds");
        sub.assert_eq(p2.urgency, 5, "urgency is 5");
        sub.assert_false(p2.incremental, "incremental defaults to false");

        // Vector 3: "i=?0, u=2"
        let p3, ok3 = wing::parse_http_priority("i=?0, u=2");
        sub.assert_true(ok3, "parse i=?0, u=2 succeeds");
        sub.assert_eq(p3.urgency, 2, "urgency is 2");
        sub.assert_false(p3.incremental, "incremental is explicitly false");

        // Vector 4: Forward compatibility - ignore unknown parameters
        let p4, ok4 = wing::parse_http_priority("future_param=123, u=7");
        sub.assert_true(ok4, "parse with unknown param succeeds");
        sub.assert_eq(p4.urgency, 7, "urgency is 7");
    };

    t.run("FRAME-04: PRIORITY_UPDATE Frame Codec Roundtrip") { sub =>
        let prio = wing::PriorityParam { urgency: 1, incremental: true };
        var payload: u8[..32] = [];
        internal::encode_priority_update_payload(42, prio, payload);

        let stream_id, parsed_prio, err = internal::parse_priority_update_payload(payload[..]);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "parse_priority_update succeeds");
        sub.assert_eq(stream_id, 42, "stream id matches 42");
        sub.assert_eq(parsed_prio.urgency, 1, "urgency matches 1");
        sub.assert_true(parsed_prio.incremental, "incremental is true");
    };

    t.run("FRAME-05: SETTINGS Parameter Boundary Validation") { sub =>
        // MAX_FRAME_SIZE below 16384 -> PROTOCOL_ERROR
        sub.assert_eq(internal::validate_settings_parameter(rfc::H2_SETTING_MAX_FRAME_SIZE, 1000), rfc::H2_ERR_PROTOCOL_ERROR);
        // MAX_FRAME_SIZE above 16777215 -> PROTOCOL_ERROR
        sub.assert_eq(internal::validate_settings_parameter(rfc::H2_SETTING_MAX_FRAME_SIZE, 20000000), rfc::H2_ERR_PROTOCOL_ERROR);
        // Valid MAX_FRAME_SIZE 65536 -> NO_ERROR
        sub.assert_eq(internal::validate_settings_parameter(rfc::H2_SETTING_MAX_FRAME_SIZE, 65536), rfc::H2_ERR_NO_ERROR);

        // INITIAL_WINDOW_SIZE > 0x7FFFFFFF -> FLOW_CONTROL_ERROR
        sub.assert_eq(internal::validate_settings_parameter(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 0x80000000), rfc::H2_ERR_FLOW_CONTROL_ERROR);

        // ENABLE_PUSH must be 0 or 1
        sub.assert_eq(internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_PUSH, 2), rfc::H2_ERR_PROTOCOL_ERROR);
        sub.assert_eq(internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_PUSH, 1), rfc::H2_ERR_NO_ERROR);
    };
}

// 4. Two-Level Signed Flow Control & Negative Window Invariant Tests
fn test_flow_control_and_session_state(t: lit::T&) {
    t.run("FLOW-01: Signed Window Deltas & Negative Window State (RFC 9113 Section 6.9.2)") { sub =>
        var sess = internal::new_session_state();

        // 1. Open stream 1
        let hdr_open = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let err_open = internal::on_ingress_frame_header(sess, hdr_open, 0);
        sub.assert_eq(err_open, rfc::H2_ERR_NO_ERROR, "open stream 1");
        sub.assert_eq(sess.streams[0].send_window, 65535, "initial send window is 65535");

        // 2. Peer decreases SETTINGS_INITIAL_WINDOW_SIZE from 65535 to 10000 (delta = -55535)
        let err_delta1 = internal::apply_peer_initial_window_size_delta(sess, 10000);
        sub.assert_eq(err_delta1, rfc::H2_ERR_NO_ERROR, "apply initial window delta 10000");
        sub.assert_eq(sess.streams[0].send_window, 10000, "stream window reduced to 10000");

        // 3. Peer decreases SETTINGS_INITIAL_WINDOW_SIZE by another 20000 to 0 (delta = -10000)
        // Then stream sends 5000 bytes so window is 5000, then delta brings it negative!
        sess.streams[0].send_window = 5000;
        let err_delta2 = internal::apply_peer_initial_window_size_delta(sess, 0);
        sub.assert_eq(err_delta2, rfc::H2_ERR_NO_ERROR, "initial window delta to 0");
        sub.assert_eq(sess.streams[0].send_window, -5000, "stream window is legitimately negative (-5000)");

        // 4. While stream send window is negative, effective quota must be 0
        let quota = internal::compute_stream_send_quota(sess, 1);
        sub.assert_eq(quota, 0, "quota with negative window is 0");

        // 5. WINDOW_UPDATE restores stream window to positive (+3000)
        let err_up = internal::apply_window_update(sess, 1, 8000);
        sub.assert_eq(err_up, rfc::H2_ERR_NO_ERROR, "window update +8000");
        sub.assert_eq(sess.streams[0].send_window, 3000, "stream window restored to +3000");

        let quota_restored = internal::compute_stream_send_quota(sess, 1);
        sub.assert_eq(quota_restored, 3000, "quota is now 3000");
    };

    t.run("FLOW-02: Window Update Overflow Rejection (Go #58456)") { sub =>
        var sess = internal::new_session_state();
        // Conn send window is 65535. Adding 0x7FFFFFFF will overflow > 2^31 - 1
        let err_ovf = internal::apply_window_update(sess, 0, 0x7FFFFFFF);
        sub.assert_eq(err_ovf, rfc::H2_ERR_FLOW_CONTROL_ERROR, "window update causing overflow must trigger FLOW_CONTROL_ERROR");

        // Window update with increment = 0 -> PROTOCOL_ERROR
        let err_zero = internal::apply_window_update(sess, 0, 0);
        sub.assert_eq(err_zero, rfc::H2_ERR_PROTOCOL_ERROR, "window update increment 0 must trigger PROTOCOL_ERROR");
    };
}

// 5. RFC 9218 Extensible Write Scheduler Tests
fn test_rfc9218_write_scheduler(t: lit::T&) {
    t.run("SCHED-01: Urgency 0..7 Priority Ordering") { sub =>
        var sess = internal::new_session_state();

        // Open stream 1 (urgency 3 by default)
        let h1 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);

        // Open stream 3 (set to urgency 0 - urgent)
        let h3 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 3 };
        internal::on_ingress_frame_header(sess, h3, 0);
        internal::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 0, incremental: false });

        sess.streams[0].pending_send_bytes = 1000; // stream 1
        sess.streams[1].pending_send_bytes = 1000; // stream 3

        // Schedule next write: Stream 3 (urgency 0) MUST be scheduled before Stream 1 (urgency 3)
        let target_id, send_len, ok = internal::schedule_next_write(sess, 16384);
        sub.assert_true(ok, "schedule succeeds");
        sub.assert_eq(target_id, 3, "urgency 0 stream scheduled first");
        sub.assert_eq(send_len, 1000, "1000 bytes sent");
    };

    t.run("SCHED-02: Starvation Prevention Between Incremental and Non-Incremental") { sub =>
        var sess = internal::new_session_state();

        // Stream 1: urgency 1, non-incremental, 2000 bytes
        let h1 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);
        internal::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 1, incremental: false });
        sess.streams[0].pending_send_bytes = 2000;

        // Stream 3: urgency 1, incremental, 2000 bytes
        let h3 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 3 };
        internal::on_ingress_frame_header(sess, h3, 0);
        internal::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 1, incremental: true });
        sess.streams[1].pending_send_bytes = 2000;

        // Frame slice size 500
        let id1, _, _ = internal::schedule_next_write(sess, 500);
        let id2, _, _ = internal::schedule_next_write(sess, 500);

        // One must be 1, the other 3 (alternating turns)
        sub.assert_true(id1 != id2, "scheduler alternates turns between incremental and non-incremental streams");
        sub.assert_true((id1 == 1 && id2 == 3) || (id1 == 3 && id2 == 1), "both streams get scheduled in turn");
    };

    t.run("SCHED-03: Round-Robin Multiplexing Among Concurrent Incremental Streams (RFC 9218 §4.2)") { sub =>
        var sess = internal::new_session_state();

        // Stream 1: urgency 2, incremental, 1000 bytes
        let h1 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);
        internal::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 2, incremental: true });
        sess.streams[0].pending_send_bytes = 1000;

        // Stream 3: urgency 2, incremental, 1000 bytes
        let h3 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 3 };
        internal::on_ingress_frame_header(sess, h3, 0);
        internal::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 2, incremental: true });
        sess.streams[1].pending_send_bytes = 1000;

        // Schedule round 1 & 2: each stream should get scheduled in round-robin order
        let id1, _, ok1 = internal::schedule_next_write(sess, 200);
        let id2, _, ok2 = internal::schedule_next_write(sess, 200);
        let id3, _, ok3 = internal::schedule_next_write(sess, 200);
        let id4, _, ok4 = internal::schedule_next_write(sess, 200);

        sub.assert_true(ok1 && ok2 && ok3 && ok4, "all 4 scheduling rounds succeeded");
        sub.assert_eq(id1, 1, "first round-robin choice is stream 1");
        sub.assert_eq(id2, 3, "second round-robin choice is stream 3");
        sub.assert_eq(id3, 1, "third round-robin choice rotates back to stream 1");
        sub.assert_eq(id4, 3, "fourth round-robin choice rotates back to stream 3");
    };

    t.run("SCHED-04: Anti-Starvation Credit Yield Across Urgency Levels") { sub =>
        var sess = internal::new_session_state();

        // Stream 1: high urgency 0, non-incremental, large payload (20000 bytes)
        let h1 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);
        internal::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 0, incremental: false });
        sess.streams[0].pending_send_bytes = 20000;

        // Stream 3: lower urgency 3, non-incremental, small payload (500 bytes)
        let h3 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 3 };
        internal::on_ingress_frame_header(sess, h3, 0);
        internal::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 3, incremental: false });
        sess.streams[1].pending_send_bytes = 500;

        // Run 16 consecutive frames for stream 1
        for i in 16 {
            let id, _, ok = internal::schedule_next_write(sess, 100);
            sub.assert_true(ok, "scheduled high urgency frame");
            sub.assert_eq(id, 1, "stream 1 scheduled");
        }

        // Frame 17 MUST trigger anti-starvation yield to lower urgency stream 3!
        let id17, _, ok17 = internal::schedule_next_write(sess, 100);
        sub.assert_true(ok17, "frame 17 scheduled");
        sub.assert_eq(id17, 3, "frame 17 yielded to lower-urgency stream 3 to prevent starvation");
    };
}

// 6. Anti-DoS Engine & Resource Quota Tests
fn test_anti_dos_mitigations(t: lit::T&) {
    t.run("DOS-01: Rapid Reset Token Bucket Defense (CVE-2023-44487)") { sub =>
        // Session with small reset burst = 5
        var sess = internal::SessionState {
            reset_limiter: core::TokenBucket { tokens: 5, burst: 5, rate_per_sec: 1, last_refill_ms: 0 },
            ..
        };

        // Open stream 1 then reset it
        let h_open = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h_open, 0);

        // Exhaust tokens (5 RST_STREAMs on stream 1)
        var i: u32 = 0;
        while i < 5 {
            let rst = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_RST_STREAM, flags: 0, stream_id: 1 };
            let err = internal::on_ingress_frame_header(sess, rst, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "allowed within burst limit");
            i++;
        }

        // 6th RST_STREAM without time advance -> ENHANCE_YOUR_CALM
        let rst_flood = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_RST_STREAM, flags: 0, stream_id: 1 };
        let err_flood = internal::on_ingress_frame_header(sess, rst_flood, 0);
        sub.assert_eq(err_flood, rfc::H2_ERR_ENHANCE_YOUR_CALM, "rapid reset flood must trigger ENHANCE_YOUR_CALM");
    };

    t.run("DOS-02: CONTINUATION Flood Guard (CVE-2024-28182)") { sub =>
        var sess = internal::new_session_state();

        // Initial HEADERS on stream 1 without END_HEADERS (enters ExpectContinuation)
        let h1 = internal::FrameHeader { length: 100, frame_type: rfc::H2_FRAME_HEADERS, flags: 0, stream_id: 1 };
        let err0 = internal::on_ingress_frame_header(sess, h1, 0);
        sub.assert_eq(err0, rfc::H2_ERR_NO_ERROR, "headers accepted");

        // Send MAX_CONT_FRAMES_LIMIT (16) CONTINUATION frames
        var i: u32 = 0;
        while i < internal::MAX_CONT_FRAMES_LIMIT {
            let c = internal::FrameHeader { length: 10, frame_type: rfc::H2_FRAME_CONTINUATION, flags: 0, stream_id: 1 };
            let err = internal::on_ingress_frame_header(sess, c, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "continuation within limit accepted");
            i++;
        }

        // 17th CONTINUATION frame -> ENHANCE_YOUR_CALM
        let c_flood = internal::FrameHeader { length: 10, frame_type: rfc::H2_FRAME_CONTINUATION, flags: 0, stream_id: 1 };
        let err_flood = internal::on_ingress_frame_header(sess, c_flood, 0);
        sub.assert_eq(err_flood, rfc::H2_ERR_ENHANCE_YOUR_CALM, "excess CONTINUATION frames trigger ENHANCE_YOUR_CALM");
    };

    t.run("DOS-03: Slow-Drip CONTINUATION Defense (CVE-2024-27983)") { sub =>
        var sess = internal::new_session_state(0, 8192);

        // Start CONTINUATION block at now_ms = 0
        let h1 = internal::FrameHeader { length: 10, frame_type: rfc::H2_FRAME_HEADERS, flags: 0, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);

        // Second CONTINUATION arrives after 15,000 ms (> 10,000 ms max_header_block_duration_ms)
        let c_slow = internal::FrameHeader { length: 10, frame_type: rfc::H2_FRAME_CONTINUATION, flags: 0, stream_id: 1 };
        let err_slow = internal::on_ingress_frame_header(sess, c_slow, 15000);
        sub.assert_eq(err_slow, rfc::H2_ERR_ENHANCE_YOUR_CALM, "slow-drip header block retention triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-04: Stream Interleaving Rejection During CONTINUATION (RFC 9113 Section 6.10)") { sub =>
        var sess = internal::new_session_state();

        // HEADERS on stream 1 expecting CONTINUATION
        let h1 = internal::FrameHeader { length: 10, frame_type: rfc::H2_FRAME_HEADERS, flags: 0, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);

        // Interleaved DATA frame on stream 1
        let d = internal::FrameHeader { length: 10, frame_type: rfc::H2_FRAME_DATA, flags: 0, stream_id: 1 };
        let err_d = internal::on_ingress_frame_header(sess, d, 0);
        sub.assert_eq(err_d, rfc::H2_ERR_PROTOCOL_ERROR, "interleaved DATA frame triggers PROTOCOL_ERROR");
    };

    t.run("DOS-05: Empty Frame Flooding Defense (CVE-2019-9518)") { sub =>
        var sess = internal::new_session_state();

        // Send 8 empty DATA frames without END_STREAM (allowed)
        var i: u32 = 0;
        while i < internal::MAX_EMPTY_FRAME_STREAK {
            let empty_data = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_DATA, flags: 0, stream_id: 1 };
            let err = internal::on_ingress_frame_header(sess, empty_data, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "empty frame streak within limit");
            i++;
        }

        // 9th empty DATA frame -> ENHANCE_YOUR_CALM
        let empty_streak = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_DATA, flags: 0, stream_id: 1 };
        let err_streak = internal::on_ingress_frame_header(sess, empty_streak, 0);
        sub.assert_eq(err_streak, rfc::H2_ERR_ENHANCE_YOUR_CALM, "empty frame flood streak triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-06: PING / SETTINGS Flood Defense (CVE-2019-9512 / CVE-2019-9515)") { sub =>
        var sess = internal::new_session_state();

        // Send 64 unacknowledged PING frames
        var i: u32 = 0;
        while i < internal::MAX_PENDING_CTRL_FRAMES {
            let ping = internal::FrameHeader { length: 8, frame_type: rfc::H2_FRAME_PING, flags: 0, stream_id: 0 };
            let err = internal::on_ingress_frame_header(sess, ping, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "ping within control frame quota");
            i++;
        }

        // 65th unacknowledged PING -> ENHANCE_YOUR_CALM
        let ping_flood = internal::FrameHeader { length: 8, frame_type: rfc::H2_FRAME_PING, flags: 0, stream_id: 0 };
        let err_flood = internal::on_ingress_frame_header(sess, ping_flood, 0);
        sub.assert_eq(err_flood, rfc::H2_ERR_ENHANCE_YOUR_CALM, "unacknowledged control frame flood triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-07: PING / SETTINGS with FLAG_ACK Do Not Increment Pending Counter") { sub =>
        var sess = internal::new_session_state();

        // Send 100 PING frames with FLAG_ACK (e.g. peer confirming our pings)
        var i: u32 = 0;
        while i < 100 {
            let ping_ack = internal::FrameHeader { length: 8, frame_type: rfc::H2_FRAME_PING, flags: rfc::H2_FLAG_ACK, stream_id: 0 };
            let err = internal::on_ingress_frame_header(sess, ping_ack, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "ping ack must be accepted without limit");
            i++;
        }
        sub.assert_eq(sess.pending_control_frames, 0, "pending_control_frames remains 0 for ACKs");

        // Send 100 SETTINGS frames with FLAG_ACK
        var j: u32 = 0;
        while j < 100 {
            let set_ack = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: rfc::H2_FLAG_ACK, stream_id: 0 };
            let err = internal::on_ingress_frame_header(sess, set_ack, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "settings ack must be accepted without limit");
            j++;
        }
        sub.assert_eq(sess.pending_control_frames, 0, "pending_control_frames remains 0 for SETTINGS ACKs");
    };

    t.run("DOS-08: Ingress Frame Size Check on HEADERS and CONTINUATION (RFC 9113 §4.2)") { sub =>
        var sess = internal::new_session_state();
        // local_max_frame_size = 16384 by default
        let big_headers = internal::FrameHeader { length: 20000, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        let err_h = internal::on_ingress_frame_header(sess, big_headers, 0);
        sub.assert_eq(err_h, rfc::H2_ERR_FRAME_SIZE_ERROR, "HEADERS frame exceeding max frame size rejected with FRAME_SIZE_ERROR");

        let big_cont = internal::FrameHeader { length: 20000, frame_type: rfc::H2_FRAME_CONTINUATION, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        let err_c = internal::on_ingress_frame_header(sess, big_cont, 0);
        sub.assert_eq(err_c, rfc::H2_ERR_FRAME_SIZE_ERROR, "CONTINUATION frame exceeding max frame size rejected with FRAME_SIZE_ERROR");
    };

    t.run("DOS-09: Stream Capacity 128 and Slot Reclamation on Full Close") { sub =>
        var sess = internal::new_session_state();
        sub.assert_eq(sess.streams.cap, 128, "streams storage capacity is 128");

        // Open 128 concurrent streams
        var sid: u32 = 1;
        while sid <= 255 {
            let h = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: sid };
            let err = internal::on_ingress_frame_header(sess, h, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "stream opened");
            sid += 2;
        }
        sub.assert_eq(sess.active_stream_count, 128, "all 128 streams active");

        // 129th stream rejected with REFUSED_STREAM
        let h_129 = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 257 };
        let err_129 = internal::on_ingress_frame_header(sess, h_129, 0);
        sub.assert_eq(err_129, rfc::H2_ERR_REFUSED_STREAM, "129th stream refused due to max_concurrent_streams");

        // Close local side, then peer sends DATA with FLAG_END_STREAM
        internal::close_local_stream(sess, 1);
        let end_data = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_DATA, flags: rfc::H2_FLAG_END_STREAM, stream_id: 1 };
        let d_err = internal::on_data_frame_received(sess, end_data, 0);
        sub.assert_eq(d_err, rfc::H2_ERR_NO_ERROR, "data with end_stream processed");
        sub.assert_eq(sess.active_stream_count, 127, "active_stream_count decremented on full close");

        // Now stream 257 can be accepted in reclaimed slot
        let err_reopen = internal::on_ingress_frame_header(sess, h_129, 0);
        sub.assert_eq(err_reopen, rfc::H2_ERR_NO_ERROR, "slot reclaimed, new stream accepted");
        sub.assert_eq(sess.active_stream_count, 128, "active count restored to 128");
    };
}

// --- Component: http2_server ---
// tests/h2_server_test.goose
// Verification test suite for HTTP/2 Server Frame Multiplexer (RFC 9113 & RFC 7541).

// Helper to encode a client request HEADERS frame
fn encode_client_headers<B>(
    dt:         internal::DynamicTable&,
    stream_id:  u32,
    method:     const u8[:],
    path:       const u8[:],
    authority:  const u8[:],
    end_stream: bool,
    out:        B&,
) {
    var hdr_block: u8[>..] = [];
    internal::encode_hpack_field(dt, hdr_block, ":method", method, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hdr_block, ":path", path, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hdr_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hdr_block, ":authority", authority, internal::HpackIndexing.Incremental, false);

    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if end_stream {
        flags |= rfc::H2_FLAG_END_STREAM;
    }

    let hdr = internal::FrameHeader {
        length:     hdr_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hdr_block[..]);
}

// Helper to encode a client DATA frame
fn encode_client_data<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) {
    let flags: u8 = if end_stream { rfc::H2_FLAG_END_STREAM } else { 0 };
    let hdr = internal::FrameHeader {
        length:     payload.len as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      flags,
        stream_id:  stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(payload);
}

// Helper to encode client trailers in a HEADERS frame
fn encode_client_trailers<B>(
    dt:        internal::DynamicTable&,
    stream_id: u32,
    name:      const u8[:],
    value:     const u8[:],
    out:       B&,
) {
    var hdr_block: u8[>..] = [];
    internal::encode_hpack_field(dt, hdr_block, name, value, internal::HpackIndexing.Incremental, false);
    let hdr = internal::FrameHeader {
        length:     hdr_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hdr_block[..]);
}

// 7. Connection Preface, Handshake & Settings Negotiation
fn test_h2_handshake_and_settings(t: lit::T&) {
    t.run("H2-01: Preface & Initial Server SETTINGS emission") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var out_wire: u8[..512] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", rfc::H2_CLIENT_PREFACE[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on preface");
        sub.assert_eq(consumed, 24, "Consumed 24 bytes of client preface");
        sub.assert_true(sess.preface_handled, "preface_handled flag is true");
        sub.assert_true(sess.server_settings_sent, "server_settings_sent flag is true");

        // Server must emit SETTINGS frame (type 0x04, length 24, stream 0)
        sub.assert_ge(out_wire.len, 9, "Output has frame header");
        let f_hdr, err_f = internal::parse_frame_header(out_wire[..9]);
        sub.assert_eq(err_f, rfc::H2_ERR_NO_ERROR, "Decoded frame header");
        sub.assert_eq(f_hdr.frame_type, rfc::H2_FRAME_SETTINGS, "Frame is SETTINGS");
        sub.assert_eq(f_hdr.stream_id, 0, "SETTINGS on stream 0");
        sub.assert_eq(f_hdr.length, 24, "SETTINGS payload is 24 bytes (4 settings)");
    };

    t.run("H2-02: Client SETTINGS ACK & PING ACK") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Prepend preface
        var wire: u8[..512] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Client SETTINGS (empty)
        let s_hdr = internal::FrameHeader {
            length:     0,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(s_hdr, wire);

        // Client PING with 8-byte opaque data
        let p_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(p_hdr, wire);
        let ping_data: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        for b in ping_data { wire.push(b); }

        var out_wire: u8[..512] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on preface + settings + ping");
        sub.assert_eq(consumed, wire.len, "Consumed full wire");

        // Inspect emitted frames:
        // Frame 1: Server SETTINGS (9 header + 24 payload = 33)
        // Frame 2: Server SETTINGS ACK (9 header + 0 payload = 9)
        // Frame 3: Server PING ACK (9 header + 8 payload = 17)
        sub.assert_ge(out_wire.len, 33 + 9 + 17, "Output has all 3 response frames");

        // Check Frame 2 (SETTINGS ACK)
        let f2_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(f2_hdr.frame_type, rfc::H2_FRAME_SETTINGS, "Frame 2 is SETTINGS");
        sub.assert_true((f2_hdr.flags & rfc::H2_FLAG_ACK) != 0, "Frame 2 has FLAG_ACK");

        // Check Frame 3 (PING ACK)
        let f3_hdr, _ = internal::parse_frame_header(out_wire[42..51]);
        sub.assert_eq(f3_hdr.frame_type, rfc::H2_FRAME_PING, "Frame 3 is PING");
        sub.assert_true((f3_hdr.flags & rfc::H2_FLAG_ACK) != 0, "Frame 3 has FLAG_ACK");
        let ping_echo = out_wire[51..59];
        sub.assert_eq(ping_echo[0], 0x11, "PING opaque byte 0 matched");
        sub.assert_eq(ping_echo[7], 0x88, "PING opaque byte 7 matched");
    };

    t.run("H2-02b: Outbound Frame Aggregation with Zero-Heap CorkBuffer") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[..256] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        let p_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(p_hdr, wire);
        let ping_data: u8[8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        for b in ping_data { wire.push(b); }

        var cork = core::new_cork_buffer();
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, cork);

        sub.assert_true(ok, "Ingress succeeded with CorkBuffer");
        sub.assert_eq(consumed, wire.len, "Consumed entire client payload");
        sub.assert_gt(cork.cork_pending(), 0, "CorkBuffer contains emitted frames");

        let emitted = cork.cork_as_slice();
        // Frame 1: Server SETTINGS (33 bytes)
        // Frame 2: Server PING ACK (17 bytes)
        sub.assert_eq(cork.cork_pending(), 33 + 17, "Emitted SETTINGS (33) + PING ACK (17)");
        let f2_hdr, _ = internal::parse_frame_header(emitted[33..42]);
        sub.assert_eq(f2_hdr.frame_type, rfc::H2_FRAME_PING, "Frame 2 is PING ACK in cork");
        sub.assert_true((f2_hdr.flags & rfc::H2_FLAG_ACK) != 0, "FLAG_ACK set on PING response");

        core::cork_consume(cork, 33);
        sub.assert_eq(cork.cork_pending(), 17, "Remaining 17 bytes after partial cork consume");
    };
}

// 8. Stream Multiplexing, Request Dispatching & HPACK Response Generation
fn test_h2_request_dispatch(t: lit::T&) {
    t.run("H2-03: Single GET Request through Server Pipeline") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/api/greet", 101);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/api/greet", "127.0.0.1:8080", true, wire);

        var out_wire: u8[..1024] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "handle_h2_server_ingress succeeds on GET request");
        sub.assert_eq(consumed, wire.len, "Consumed entire client stream");

        // The response must contain:
        // 1. Server SETTINGS frame (33 bytes)
        // 2. Response HEADERS frame for stream 1
        sub.assert_gt(out_wire.len, 33, "Response has frames beyond initial SETTINGS");

        let resp_hdr, err_rh = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(err_rh, rfc::H2_ERR_NO_ERROR, "Decoded response frame header");
        sub.assert_eq(resp_hdr.frame_type, rfc::H2_FRAME_HEADERS, "Response frame is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
        sub.assert_true((resp_hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0, "Response has END_HEADERS");

        // Decode response headers with client HPACK table
        var dec_pseudo = internal::H2PseudoHeaders { .. };
        var dec_resp = wing::HeaderMap { .. };
        let hpack_payload = out_wire[42..42 + resp_hdr.length];
        let dec_err = internal::decode_hpack_to_map(client_hpack, hpack_payload, dec_pseudo, dec_resp);
        sub.assert_eq(dec_err, rfc::H2_ERR_NO_ERROR, "Client decoded response HPACK without error");

        // Verify :status == 200
        sub.assert_true(dec_pseudo.has_status, "Found :status in response headers");
        sub.assert_eq(dec_pseudo.status, 200, ":status is 200");
    };

    t.run("H2-04: POST Request with DATA Frame Payload") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/api/data", 202);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        // Headers without END_STREAM
        encode_client_headers(client_hpack, 1, "POST", "/api/data", "127.0.0.1:8080", false, wire);
        // Data with END_STREAM
        encode_client_data(1, "payload_bytes_12345", true, wire);

        var out_wire: u8[..1024] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "handle_h2_server_ingress succeeds on POST with DATA");
        sub.assert_eq(consumed, wire.len, "Consumed entire client stream");
        sub.assert_gt(out_wire.len, 33, "Generated response");
    };

    t.run("H2-05: Concurrent Multiplexed Streams (Streams 1 and 3)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/first", 1);
        wing::add_route(pipeline.router, "GET", "/second", 2);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..1024] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        // Interleaved streams 1 and 3
        encode_client_headers(client_hpack, 1, "GET", "/first", "localhost", true, wire);
        encode_client_headers(client_hpack, 3, "GET", "/second", "localhost", true, wire);

        var out_wire: u8[..2048] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Both streams handled concurrently");
        sub.assert_eq(consumed, wire.len, "Consumed all incoming bytes");

        // Verify responses were emitted for both stream 1 and stream 3
        var found_stream_1 = false;
        var found_stream_3 = false;
        var off: i64 = 33; // skip Server SETTINGS (33B)

        while off + 9 <= out_wire.len {
            let f_hdr, err_f = internal::parse_frame_header(out_wire[off..off + 9]);
            if err_f == rfc::H2_ERR_NO_ERROR && f_hdr.frame_type == rfc::H2_FRAME_HEADERS {
                if f_hdr.stream_id == 1 { found_stream_1 = true; }
                if f_hdr.stream_id == 3 { found_stream_3 = true; }
            }
            off += 9 + (f_hdr.length as i64);
        }

        sub.assert_true(found_stream_1, "Found response HEADERS on stream 1");
        sub.assert_true(found_stream_3, "Found response HEADERS on stream 3");
    };
}

// 9. End-to-End HttpServer Integration with HTTP/2 Preface Detection
fn test_h2_server_wire_integration(t: lit::T&) {
    t.run("HttpServer.handle_connection_wire auto-detects H2 and serves requests") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/ping", 999);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire_in: u8[..512] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/ping", "127.0.0.1", true, wire_in);

        var wire_out: u8[..1024] = [];
        let outcome, ok = wing::handle_connection_wire(server, "127.0.0.1", wire_in[..], 1700000000000000, wire_out);

        sub.assert_true(ok, "handle_connection_wire succeeded on HTTP/2 stream");
        sub.assert_true(outcome == wing::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_gt(wire_out.len, 33, "Generated HTTP/2 response frames");
        sub.assert_ge(server.requests_processed, 1, "Requests processed incremented");
    };
}

// 10. CONTINUATION Assembly, Anti-DoS & Rapid Reset Defense
fn test_h2_continuation_and_anti_dos(t: lit::T&) {
    t.run("H2-06: Multi-Frame CONTINUATION Header Assembly") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/split/headers", 200);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

        // Prepend preface
        var wire: u8[..1024] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Encode full header block
        var hdr_block: u8[..512] = [];
        internal::encode_hpack_field(client_hpack, hdr_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hdr_block, ":path", "/split/headers", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hdr_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hdr_block, ":authority", "localhost", internal::HpackIndexing.Incremental, false);

        sub.assert_gt(hdr_block.len, 10, "Header block non-empty");

        // Split header block into two frames:
        // Frame 1: HEADERS (first 10 bytes, flags: END_STREAM, NO END_HEADERS)
        let part1 = hdr_block[..10];
        let part2 = hdr_block[10..];

        let h_hdr = internal::FrameHeader {
            length:     part1.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_STREAM, // No FLAG_END_HEADERS!
            stream_id:  1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        wire.append(part1);

        // Frame 2: CONTINUATION (remaining bytes, flags: END_HEADERS)
        let c_hdr = internal::FrameHeader {
            length:     part2.len as u32,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      rfc::H2_FLAG_END_HEADERS, // Terminal CONTINUATION frame
            stream_id:  1,
        };
        internal::encode_frame_header_to(c_hdr, wire);
        wire.append(part2);

        var out_wire: u8[..1024] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on multi-frame CONTINUATION");
        sub.assert_eq(consumed, wire.len, "Consumed entire multi-frame payload");

        // Verify response was emitted for stream 1
        sub.assert_gt(out_wire.len, 33, "Emitted response frame");
        let resp_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(resp_hdr.frame_type, rfc::H2_FRAME_HEADERS, "Response is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
    };

    t.run("H2-07: Ban Zero-Length Non-Terminal CONTINUATION (CVE-2024-2758 / CVE-2024-31309)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[..512] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS without END_HEADERS
        let h_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0,
            stream_id:  1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        // Frame 2: Zero-length non-terminal CONTINUATION frame (CVE-2024-2758 exploit attempt)
        let c_hdr = internal::FrameHeader {
            length:     0,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      0, // No END_HEADERS!
            stream_id:  1,
        };
        internal::encode_frame_header_to(c_hdr, wire);

        var out_wire: u8[..512] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        // Must reject with GOAWAY PROTOCOL_ERROR
        sub.assert_false(ok, "Ingress rejected zero-length non-terminal CONTINUATION");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
    };

    t.run("H2-08: Rapid Reset Batch Bypass (CVE-2023-44487)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/fast/reset", 50);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS stream 1
        encode_client_headers(client_hpack, 1, "GET", "/fast/reset", "localhost", true, wire);

        // Frame 2: Immediate RST_STREAM stream 1 (Rapid Reset attack pattern)
        let rst_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_RST_STREAM,
            flags:      0,
            stream_id:  1,
        };
        internal::encode_frame_header_to(rst_hdr, wire);
        let err_code: u8[4] = [0x00, 0x00, 0x00, 0x08]; // CANCEL (0x8)
        for b in err_code { wire.push(b); }

        var out_wire: u8[..512] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress safely handled rapid reset batch");
        sub.assert_eq(consumed, wire.len, "Consumed entire batch");

        // Server SETTINGS was emitted (33 bytes), but NO stream response was dispatched for stream 1!
        sub.assert_eq(out_wire.len, 33, "No response pipeline dispatch occurred for cancelled stream");
    };
}

// 11. RFC 9113 Protocol Invariants & Zero-Allocation Ingress
fn test_h2_protocol_invariants(t: lit::T&) {
    t.run("H2-09: Client Request Trailers Accepted (RFC 9113 §8.1.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/upload/trailers", 10);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/upload/trailers", "localhost", false, wire);
        encode_client_data(1, "body-content-here", false, wire);
        encode_client_trailers(client_hpack, 1, "x-checksum", "sha256-abc12345", wire);

        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on request with trailers");
        var found_resp = false;
        var off: i64 = 33; // skip server SETTINGS (33B)
        while off + 9 <= out_wire.len {
            let f_hdr, err_f = internal::parse_frame_header(out_wire[off..off + 9]);
            if err_f == rfc::H2_ERR_NO_ERROR && f_hdr.frame_type == rfc::H2_FRAME_HEADERS && f_hdr.stream_id == 1 {
                found_resp = true;
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_resp, "Response HEADERS frame emitted on stream 1");
    };

    t.run("H2-10: Client Trailers with Pseudo-Headers Rejected (RFC 9113 §8.1.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/upload/pseudo-trailer", 11);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/upload/pseudo-trailer", "localhost", false, wire);
        encode_client_trailers(client_hpack, 1, ":status", "200", wire);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress remained alive on stream error");
        sub.assert_gt(out_wire.len, 33, "Output generated");
        let rst_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, rfc::H2_FRAME_RST_STREAM, "Emitted RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 1, "RST_STREAM on stream 1");
    };

    t.run("H2-11: Large Flow Control Ingress Window Replenishment (RFC 9113 §6.9)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/bulk", 12);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/bulk", "localhost", false, wire);

        var chunk: u8[>..] = [];
        for i in 15000 { chunk.push('X'); }
        for step in 5 {
            let is_last = (step == 4);
            encode_client_data(1, chunk[..], is_last, wire);
        }

        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress handled >65535 bytes without FLOW_CONTROL_ERROR");
        sub.assert_eq(consumed, wire.len, "Consumed entire 75KB wire");
        sub.assert_ge(sess.conn.conn_recv_window, 0, "conn_recv_window replenished");
    };

    t.run("H2-12: Stream State Transition to Closed (RFC 9113 §5.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 13);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        var out_wire: u8[>..] = [];
        internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        var all_ok = true;
        for i in 135 {
            let s_id: u32 = ((i * 2) + 1) as u32;
            var s_wire: u8[>..] = [];
            encode_client_headers(client_hpack, s_id, "GET", "/test", "localhost", true, s_wire);
            var s_out: u8[>..] = [];
            let _, ok_st = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", s_wire[..], 1000, s_out);
            if !ok_st {
                all_ok = false;
                break;
            }
        }
        sub.assert_true(all_ok, "135 sequential streams processed without stream leak or REFUSED_STREAM");
        sub.assert_eq(sess.conn.active_stream_count, 0, "All completed streams decremented active count to 0");
    };

    t.run("H2-13: Stream WINDOW_UPDATE increment 0 emits RST_STREAM (RFC 9113 §6.9)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 14);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", false, wire);

        let wu_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  1,
        };
        internal::encode_frame_header_to(wu_hdr, wire);
        let zeros: u8[4] = [0, 0, 0, 0];
        for b in zeros { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Connection remains open after stream-level WINDOW_UPDATE error");
        var found_rst = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = internal::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == rfc::H2_FRAME_RST_STREAM && f_hdr.stream_id == 1 {
                found_rst = true;
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_rst, "Server emitted RST_STREAM on stream 1");
    };

    t.run("H2-14: Client SETTINGS_ENABLE_PUSH > 1 rejected, 0 and 1 accepted (RFC 9113 §6.5.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire_ok: u8[>..] = [];
        wire_ok.append(rfc::H2_CLIENT_PREFACE[..]);
        let s_hdr = internal::FrameHeader {
            length:     6,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(s_hdr, wire_ok);
        core::append_u16_be(wire_ok, rfc::H2_SETTING_ENABLE_PUSH);
        core::append_u32_be(wire_ok, 1);

        var out_ok: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_ok[..], 1000, out_ok);
        sub.assert_true(ok1, "Server accepted client ENABLE_PUSH == 1");

        var wire: u8[>..] = [];
        internal::encode_frame_header_to(s_hdr, wire);
        core::append_u16_be(wire, rfc::H2_SETTING_ENABLE_PUSH);
        core::append_u32_be(wire, 2);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Server rejected client ENABLE_PUSH > 1");
        sub.assert_gt(out_wire.len, 0, "Emitted GOAWAY");
        let g_hdr, _ = internal::parse_frame_header(out_wire[0..9]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "GOAWAY emitted");
    };

    t.run("H2-15: gRPC Response Body Preserved Without Spurious OK (RFC 9113)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/not-found", "localhost", true, wire);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress handled request");
        var has_data = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = internal::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == rfc::H2_FRAME_DATA && f_hdr.stream_id == 1 {
                has_data = true;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_false(has_data, "No DATA frame emitted for non-200 empty response");
    };

    t.run("H2-16: PRIORITY Self-Dependency Rejection (RFC 9113 §5.3.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        let prio_hdr = internal::FrameHeader {
            length:     5,
            frame_type: rfc::H2_FRAME_PRIORITY,
            flags:      0,
            stream_id:  3,
        };
        internal::encode_frame_header_to(prio_hdr, wire);
        let prio_payload: u8[5] = [0x00, 0x00, 0x00, 0x03, 0x10];
        for b in prio_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Connection remains open");
        sub.assert_gt(out_wire.len, 33, "Output contains frames");
        let rst_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, rfc::H2_FRAME_RST_STREAM, "Frame is RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 3, "RST_STREAM on stream 3");
    };

    t.run("H2-16b: PRIORITY Frame Size Error Triggers RST_STREAM(FRAME_SIZE_ERROR) Not GOAWAY (RFC 9113 §5.4.2 & §6.3)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        // Invalid PRIORITY frame with length 4 (must be 5)
        let prio_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PRIORITY,
            flags:      0,
            stream_id:  5,
        };
        internal::encode_frame_header_to(prio_hdr, wire);
        let prio_payload: u8[4] = [0x00, 0x00, 0x00, 0x01];
        for b in prio_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Connection remains open on PRIORITY size error");
        sub.assert_gt(out_wire.len, 33, "Output contains server preface/settings + RST_STREAM");
        let rst_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, rfc::H2_FRAME_RST_STREAM, "Frame is RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 5, "RST_STREAM on stream 5");
        let err_code = ((out_wire[42] as u32) << 24) | ((out_wire[43] as u32) << 16) | ((out_wire[44] as u32) << 8) | (out_wire[45] as u32);
        sub.assert_eq(err_code, rfc::H2_ERR_FRAME_SIZE_ERROR, "RST error code is FRAME_SIZE_ERROR");
    };

    t.run("H2-CONTINUATION: PUSH_PROMISE with END_HEADERS cleared allows subsequent CONTINUATION (RFC 9113 §6.6, §6.10)") { sub =>
        var s = internal::new_h2_connection();
        s.local_max_frame_size = 16384;

        // PUSH_PROMISE on stream 1 with END_HEADERS cleared
        let pp_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      0,
            stream_id:  1,
        };
        let err_pp = internal::on_ingress_frame_header(s, pp_hdr, 1000);
        sub.assert_eq(err_pp, rfc::H2_ERR_NO_ERROR, "PUSH_PROMISE header accepted");
        sub.assert_eq(s.continuation_stream_id, 1, "continuation stream id tracked for PUSH_PROMISE");

        // Subsequent CONTINUATION frame on same stream 1
        let cont_hdr = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let err_cont = internal::on_ingress_frame_header(s, cont_hdr, 1000);
        sub.assert_eq(err_cont, rfc::H2_ERR_NO_ERROR, "subsequent CONTINUATION frame accepted");
        sub.assert_eq(s.continuation_stream_id, 0, "continuation state cleared after END_HEADERS");
    };

    t.run("H2-17: HEADERS on RST-Closed Stream Triggers RST_STREAM(STREAM_CLOSED) Not GOAWAY (RFC 9113 §5.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 17);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        // Open stream 1 and close it via RST_STREAM (RFC 9113 §5.1 / h2spec 5.1.9)
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", false, wire);
        internal::emit_rst_stream(1, rfc::H2_ERR_CANCEL, wire);

        var out_wire: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);
        sub.assert_true(ok1, "Stream 1 closed via RST_STREAM");

        // Send second HEADERS frame on now-closed stream 1
        var wire2: u8[>..] = [];
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", true, wire2);

        var out_wire2: u8[>..] = [];
        let _, ok2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out_wire2);
        sub.assert_true(ok2, "Connection remains open after HEADERS on closed stream");

        // Verify RST_STREAM was emitted for stream 1
        var found_rst = false;
        var off: i64 = 0;
        while off + 9 <= out_wire2.len {
            let f_hdr, _ = internal::parse_frame_header(out_wire2[off..off + 9]);
            if f_hdr.frame_type == rfc::H2_FRAME_RST_STREAM && f_hdr.stream_id == 1 {
                found_rst = true;
                let err_code = core::read_be_u32(out_wire2, off + 9);
                sub.assert_eq(err_code, rfc::H2_ERR_STREAM_CLOSED, "RST_STREAM error code is STREAM_CLOSED");
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_rst, "Server emitted RST_STREAM on closed stream 1");

        // Verify stream 3 still works over the same connection
        var wire3: u8[>..] = [];
        encode_client_headers(client_hpack, 3, "GET", "/test", "localhost", true, wire3);
        var out_wire3: u8[>..] = [];
        let _, ok3 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire3[..], 1000, out_wire3);
        sub.assert_true(ok3, "Subsequent stream 3 succeeds over open connection");
    };

    t.run("H2-18: Interleaved Non-CONTINUATION Frame During Header Accumulation Triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.10)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS stream 1 WITHOUT FLAG_END_HEADERS
        let h_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0, // No END_HEADERS!
            stream_id:  1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        // Frame 2: Interleaved PING frame before END_HEADERS
        let ping_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(ping_hdr, wire);
        let ping_opaque: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        for b in ping_opaque { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected interleaved frame before END_HEADERS");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire, 46);
        sub.assert_eq(err_code, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-19: Unprompted CONTINUATION Frame Triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.10)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Unprompted CONTINUATION frame without preceding HEADERS
        let c_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        internal::encode_frame_header_to(c_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected unprompted CONTINUATION");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire, 46);
        sub.assert_eq(err_code, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-20: Client PUSH_PROMISE Frame Rejected with GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.6)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Client sends PUSH_PROMISE (promised stream id = 2, dummy header fragment)
        let pp_hdr = internal::FrameHeader {
            length:     5,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        internal::encode_frame_header_to(pp_hdr, wire);
        let pp_payload: u8[5] = [0x00, 0x00, 0x00, 0x02, 0x82];
        for b in pp_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Server rejected client PUSH_PROMISE");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire, 46);
        sub.assert_eq(err_code, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-21: Duplicate / Unsolicited SETTINGS ACK Rejected with GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.5 & §10.5)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Frame 1: Valid SETTINGS ACK for server initial settings
        let ack_hdr1 = internal::FrameHeader {
            length:     0,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      rfc::H2_FLAG_ACK,
            stream_id:  0,
        };
        internal::encode_frame_header_to(ack_hdr1, wire);

        var out_wire1: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire1);
        sub.assert_true(ok1, "First SETTINGS ACK accepted");
        sub.assert_true(sess.client_settings_acked, "client_settings_acked is true");
        sub.assert_false(sess.pending_settings_ack, "pending_settings_ack is false");

        // Frame 2: Duplicate / unsolicited SETTINGS ACK
        var wire2: u8[>..] = [];
        internal::encode_frame_header_to(ack_hdr1, wire2);

        var out_wire2: u8[>..] = [];
        let _, ok2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out_wire2);
        sub.assert_false(ok2, "Duplicate SETTINGS ACK rejected");
        sub.assert_gt(out_wire2.len, 0, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire2[0..9]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire2, 13);
        sub.assert_eq(err_code, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-22: Control Frame Flood (Excess PINGs/ACKs > 64) Triggers GOAWAY(ENHANCE_YOUR_CALM) (RFC 9113 §10.5)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Send 65 PING frames in a single batch (exceeding MAX_PENDING_CTRL_FRAMES = 64)
        for i in 65 {
            let ping_hdr = internal::FrameHeader {
                length:     8,
                frame_type: rfc::H2_FRAME_PING,
                flags:      0,
                stream_id:  0,
            };
            internal::encode_frame_header_to(ping_hdr, wire);
            let ping_payload: u8[8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, (i & 0xFF) as u8];
            for b in ping_payload { wire.push(b); }
        }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Control frame flood rejected");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        // Locate GOAWAY frame
        var found_calm = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = internal::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == rfc::H2_FRAME_GOAWAY {
                let err_code = core::read_be_u32(out_wire, off + 13);
                if err_code == rfc::H2_ERR_ENHANCE_YOUR_CALM {
                    found_calm = true;
                    break;
                }
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_calm, "GOAWAY with ENHANCE_YOUR_CALM emitted for control frame flood");
    };

    t.run("H2-23: HPACK Dynamic Table Size Update Mid-Block Rejected with COMPRESSION_ERROR (RFC 7541 §4.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        let h_hdr = internal::FrameHeader {
            length:     2,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        wire.push(0x82); // Indexed header: :method: GET (sets updates_allowed = false)
        wire.push(0x20); // Dynamic Table Size Update: size 0 (ILLEGAL after regular header field)

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected mid-block dynamic table size update");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire, 46);
        sub.assert_eq(err_code, rfc::H2_ERR_COMPRESSION_ERROR, "GOAWAY code is COMPRESSION_ERROR");
    };

    t.run("H2-24: HPACK Out-of-Bounds Dynamic Table Index Lookup Rejected with COMPRESSION_ERROR (RFC 7541 §2.3.3)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        let h_hdr = internal::FrameHeader {
            length:     1,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        wire.push(0xBE); // 0x80 | 62: Indexed header lookup for index 62 when dynamic table is empty

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected out-of-bounds dynamic table index lookup");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire, 46);
        sub.assert_eq(err_code, rfc::H2_ERR_COMPRESSION_ERROR, "GOAWAY code is COMPRESSION_ERROR");
    };

    t.run("H2-25: PRIORITY_UPDATE on Stream 0 and Server-Initiated Stream Rejection (RFC 9218 §7.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Sub-test A: Prioritized Stream ID 0 must be rejected with PROTOCOL_ERROR
        var wireA: u8[>..] = [];
        wireA.append(rfc::H2_CLIENT_PREFACE[..]);
        let pu_hdrA = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PRIORITY_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(pu_hdrA, wireA);
        let zeros: u8[4] = [0, 0, 0, 0]; // Prioritized stream 0
        for b in zeros { wireA.push(b); }

        var out_wireA: u8[>..] = [];
        let _, okA = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wireA[..], 1000, out_wireA);
        sub.assert_false(okA, "PRIORITY_UPDATE identifying stream 0 rejected");
        let err_codeA = core::read_be_u32(out_wireA, 46);
        sub.assert_eq(err_codeA, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");

        // Sub-test B: Prioritized Stream ID 2 (server-initiated / even) must be rejected with PROTOCOL_ERROR
        var sessB = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wireB: u8[>..] = [];
        wireB.append(rfc::H2_CLIENT_PREFACE[..]);
        let pu_hdrB = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PRIORITY_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(pu_hdrB, wireB);
        let stream2: u8[4] = [0, 0, 0, 2]; // Even stream ID
        for b in stream2 { wireB.push(b); }

        var out_wireB: u8[>..] = [];
        let _, okB = internal::handle_h2_server_ingress(sessB, pipeline, timer, "127.0.0.1", wireB[..], 1000, out_wireB);
        sub.assert_false(okB, "PRIORITY_UPDATE identifying server-initiated stream rejected");
        let err_codeB = core::read_be_u32(out_wireB, 46);
        sub.assert_eq(err_codeB, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");

        // Sub-test C: Valid PRIORITY_UPDATE for stream 1 applies priority update
        var sessC = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wireC: u8[>..] = [];
        wireC.append(rfc::H2_CLIENT_PREFACE[..]);
        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", false, wireC);

        let pu_val: const u8[:] = "u=0, i";
        let pu_hdrC = internal::FrameHeader {
            length:     (4 + pu_val.len) as u32,
            frame_type: rfc::H2_FRAME_PRIORITY_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(pu_hdrC, wireC);
        let stream1: u8[4] = [0, 0, 0, 1];
        for b in stream1 { wireC.push(b); }
        for b in pu_val { wireC.push(b); }

        var out_wireC: u8[>..] = [];
        let _, okC = internal::handle_h2_server_ingress(sessC, pipeline, timer, "127.0.0.1", wireC[..], 1000, out_wireC);
        sub.assert_true(okC, "Valid PRIORITY_UPDATE accepted");
        let s_idx, found = internal::find_session_stream_idx(sessC.conn, 1);
        sub.assert_true(found, "Stream 1 found in connection");
        sub.assert_eq(sessC.conn.streams[s_idx].priority.urgency, 0, "Priority urgency updated to 0");
        sub.assert_true(sessC.conn.streams[s_idx].priority.incremental, "Priority incremental updated to true");
    };

    t.run("H2-26: Rapid Reset Large Batch Defense (>16 Cancellations) Handled Without Dispatch (CVE-2023-44487)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/fast/reset", 50);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Send 25 pairs of HEADERS + RST_STREAM in a single batch (exceeding old 16-element limit)
        for i in 25 {
            let s_id: u32 = ((i * 2) + 1) as u32;
            encode_client_headers(client_hpack, s_id, "GET", "/fast/reset", "localhost", true, wire);
            let rst_hdr = internal::FrameHeader {
                length:     4,
                frame_type: rfc::H2_FRAME_RST_STREAM,
                flags:      0,
                stream_id:  s_id,
            };
            internal::encode_frame_header_to(rst_hdr, wire);
            let err_code: u8[4] = [0x00, 0x00, 0x00, 0x08]; // CANCEL (0x8)
            for b in err_code { wire.push(b); }
        }

        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress safely handled 25 rapid resets in batch");
        sub.assert_eq(consumed, wire.len, "Consumed entire large rapid reset batch");
        // Output wire must ONLY contain server initial settings (33 bytes), NO response HEADERS for any of the 25 cancelled streams!
        sub.assert_eq(out_wire.len, 33, "No response pipeline dispatch occurred for any of the 25 cancelled streams");
    };

    t.run("H2-27: WINDOW_UPDATE on Closed Stream Ignored Without Error (RFC 9113 §5.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 27);

        var client_hpack = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", true, wire);

        var out_wire1: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire1);
        sub.assert_true(ok1, "Stream 1 completed normally");

        // Now stream 1 is closed. Send WINDOW_UPDATE on stream 1
        var wire2: u8[>..] = [];
        let wu_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  1,
        };
        internal::encode_frame_header_to(wu_hdr, wire2);
        core::append_u32_be(wire2, 1024);

        var out_wire2: u8[>..] = [];
        let _, ok2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out_wire2);
        sub.assert_true(ok2, "WINDOW_UPDATE on closed stream ignored cleanly");
        sub.assert_eq(out_wire2.len, 0, "No frames emitted for WINDOW_UPDATE on closed stream");
    };

    t.run("H2-28: Connection Flow Control Window Exceeding 2^31-1 Emits GOAWAY(FLOW_CONTROL_ERROR) (RFC 9113 §6.9)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        // Connection send window starts at 65535.
        // Send WINDOW_UPDATE on stream 0 with increment 0x7FFFFFFF (2^31 - 1)
        // 65535 + 2147483647 exceeds 2^31 - 1 -> FLOW_CONTROL_ERROR
        let wu_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(wu_hdr, wire);
        core::append_u32_be(wire, 0x7FFFFFFF);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Window overflow rejected");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, rfc::H2_FRAME_GOAWAY, "Frame is GOAWAY");
        let err_code = core::read_be_u32(out_wire, 46);
        sub.assert_eq(err_code, rfc::H2_ERR_FLOW_CONTROL_ERROR, "GOAWAY code is FLOW_CONTROL_ERROR");
    };
}

// --- Component: http2_security ---
// Tests for HTTP/2 framer validation and frame limits (RFC 9113).

// ----------------------------------------------------------------------------
// 12. CONTINUATION Flood & Interleaving Guard (CVE-2024-27983)
// ----------------------------------------------------------------------------
fn test_continuation_flood_and_interleaving(t: lit::T&) {
    t.run("H2-01: CONTINUATION Flood Exceeding Frame Cap Rejection (CVE-2024-27983)") { sub =>
        var conn = internal::new_h2_connection(0);

        let h_hdr = internal::FrameHeader {
            length:     100,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0x0,
            stream_id:  1,
        };
        let err0 = internal::on_ingress_frame_header(conn, h_hdr, 0);
        sub.assert_eq(err0, rfc::H2_ERR_NO_ERROR);
        sub.assert_eq(conn.continuation_stream_id, 1);

        for _ in 16 {
            let cont_hdr = internal::FrameHeader {
                length:     100,
                frame_type: rfc::H2_FRAME_CONTINUATION,
                flags:      0x0,
                stream_id:  1,
            };
            let err_cont = internal::on_ingress_frame_header(conn, cont_hdr, 0);
            sub.assert_eq(err_cont, rfc::H2_ERR_NO_ERROR);
        }

        let flood_hdr = internal::FrameHeader {
            length:     100,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      0x0,
            stream_id:  1,
        };
        let err_flood = internal::on_ingress_frame_header(conn, flood_hdr, 0);
        sub.assert_eq(err_flood, rfc::H2_ERR_ENHANCE_YOUR_CALM, "CONTINUATION flood must be rejected with EnhanceYourCalm");
    };

    t.run("H2-02: Stream Interleaving While Expecting CONTINUATION Rejection (RFC 9113 Section 4.3)") { sub =>
        var conn = internal::new_h2_connection(0);

        let h_hdr = internal::FrameHeader {
            length:     50,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0x0,
            stream_id:  1,
        };
        let _ = internal::on_ingress_frame_header(conn, h_hdr, 0);

        let data_hdr = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      0x0,
            stream_id:  1,
        };
        let err1 = internal::on_ingress_frame_header(conn, data_hdr, 0);
        sub.assert_eq(err1, rfc::H2_ERR_PROTOCOL_ERROR, "Non-CONTINUATION frame interleaved must trigger ProtocolError");

        var conn2 = internal::new_h2_connection(0);
        let _ = internal::on_ingress_frame_header(conn2, h_hdr, 0);

        let cont_other_stream = internal::FrameHeader {
            length:     50,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      0x0,
            stream_id:  3,
        };
        let err2 = internal::on_ingress_frame_header(conn2, cont_other_stream, 0);
        sub.assert_eq(err2, rfc::H2_ERR_PROTOCOL_ERROR, "CONTINUATION on different stream must trigger ProtocolError");
    };

    t.run("H2-03: Cumulative Header Block Size Bomb Rejection") { sub =>
        var conn = internal::new_h2_connection(0);

        let h_hdr = internal::FrameHeader {
            length:     4000,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0x0,
            stream_id:  1,
        };
        let _ = internal::on_ingress_frame_header(conn, h_hdr, 0);

        let cont_bomb = internal::FrameHeader {
            length:     5000,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let err = internal::on_ingress_frame_header(conn, cont_bomb, 0);
        sub.assert_eq(err, rfc::H2_ERR_ENHANCE_YOUR_CALM, "Cumulative header block > 8KB must be rejected with EnhanceYourCalm");
    };

    t.run("H2-04: Valid CONTINUATION Sequence with END_HEADERS") { sub =>
        var conn = internal::new_h2_connection(0);

        let h_hdr = internal::FrameHeader {
            length:     200,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0x0,
            stream_id:  1,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, h_hdr, 0), rfc::H2_ERR_NO_ERROR);

        let cont_final = internal::FrameHeader {
            length:     300,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, cont_final, 0), rfc::H2_ERR_NO_ERROR);
        sub.assert_eq(conn.continuation_stream_id, 0, "State returned to Idle on END_HEADERS");
    };
}

// ----------------------------------------------------------------------------
// 13. Rapid Reset & Resource DoS Floods (CVE-2023-44487 & CVE-2019-9512)
// ----------------------------------------------------------------------------
fn test_rapid_reset_and_dos_floods(t: lit::T&) {
    t.run("RESET-01: Rapid Reset Flood Defense (CVE-2023-44487)") { sub =>
        var conn = internal::new_h2_connection(0);
        conn.reset_limiter = core::TokenBucket { tokens: 100, burst: 100, rate_per_sec: 33, last_refill_ms: 0 };
        conn.last_peer_stream_id = 1;

        for _ in 100 {
            let rst = internal::FrameHeader {
                length:     4,
                frame_type: rfc::H2_FRAME_RST_STREAM,
                flags:      0x0,
                stream_id:  1,
            };
            let err = internal::on_ingress_frame_header(conn, rst, 0);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR);
        }

        let rst_flood = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_RST_STREAM,
            flags:      0x0,
            stream_id:  1,
        };
        let err_flood = internal::on_ingress_frame_header(conn, rst_flood, 0);
        sub.assert_eq(err_flood, rfc::H2_ERR_ENHANCE_YOUR_CALM, "Rapid reset flood must trigger EnhanceYourCalm");
    };

    t.run("PING-01: PING Flood Defense (CVE-2019-9512)") { sub =>
        var conn = internal::new_h2_connection(0);

        for _ in 64 {
            let ping = internal::FrameHeader {
                length:     8,
                frame_type: rfc::H2_FRAME_PING,
                flags:      0x0,
                stream_id:  0,
            };
            sub.assert_eq(internal::on_ingress_frame_header(conn, ping, 0), rfc::H2_ERR_NO_ERROR);
        }

        let ping_flood = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0x0,
            stream_id:  0,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, ping_flood, 0), rfc::H2_ERR_ENHANCE_YOUR_CALM);
    };
}

// ----------------------------------------------------------------------------
// 14. SETTINGS & Stream ID Invariants
// ----------------------------------------------------------------------------
fn test_settings_and_stream_id_invariants(t: lit::T&) {
    t.run("SETTING-01: SETTINGS_MAX_FRAME_SIZE=0 Infinite Loop Defense ") { sub =>
        let err0 = internal::validate_settings_parameter(0x5, 0);
        sub.assert_eq(err0, rfc::H2_ERR_PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE=0 must return ProtocolError");

        let err1 = internal::validate_settings_parameter(0x5, 1000);
        sub.assert_eq(err1, rfc::H2_ERR_PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE < 16384 must return ProtocolError");

        let err_min = internal::validate_settings_parameter(0x5, 16384);
        sub.assert_eq(err_min, rfc::H2_ERR_NO_ERROR, "SETTINGS_MAX_FRAME_SIZE=16384 is valid");

        let err_max = internal::validate_settings_parameter(0x5, 16777215);
        sub.assert_eq(err_max, rfc::H2_ERR_NO_ERROR, "SETTINGS_MAX_FRAME_SIZE=16777215 is valid");

        let err_ovf = internal::validate_settings_parameter(0x5, 20000000);
        sub.assert_eq(err_ovf, rfc::H2_ERR_PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE > 16777215 must return ProtocolError");
    };

    t.run("STREAM-01: Stream ID Parity & Connection-Level Isolation (RFC 9113 Section 5.1.1)") { sub =>
        var conn = internal::new_h2_connection(0);

        let even_hdr = internal::FrameHeader {
            length:     20,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  2,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, even_hdr, 0), rfc::H2_ERR_PROTOCOL_ERROR, "Client HEADERS on even stream must fail");

        let stream0_hdr = internal::FrameHeader {
            length:     20,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  0,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, stream0_hdr, 0), rfc::H2_ERR_PROTOCOL_ERROR, "HEADERS on stream 0 must fail");

        let s_hdr = internal::FrameHeader {
            length:     6,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0x0,
            stream_id:  1,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, s_hdr, 0), rfc::H2_ERR_PROTOCOL_ERROR, "SETTINGS on stream 1 must fail");
    };
}

// ----------------------------------------------------------------------------
// 15. Frame Header Parsing & Type Mapping (RFC 9113)
// ----------------------------------------------------------------------------
fn test_h2_wire_framing_and_types(t: lit::T&) {
    t.run("WIRE-01: Frame Type Mapping and Extension Handling (RFC 9113 Sec 6)") { sub =>
        sub.assert_eq(rfc::H2_FRAME_DATA, 0x0, "0x0 is Data");
        sub.assert_eq(rfc::H2_FRAME_HEADERS, 0x1, "0x1 is Headers");
        sub.assert_eq(rfc::H2_FRAME_PRIORITY, 0x2, "0x2 is Priority");
        sub.assert_eq(rfc::H2_FRAME_RST_STREAM, 0x3, "0x3 is RstStream");
        sub.assert_eq(rfc::H2_FRAME_SETTINGS, 0x4, "0x4 is Settings");
        sub.assert_eq(rfc::H2_FRAME_PUSH_PROMISE, 0x5, "0x5 is PushPromise");
        sub.assert_eq(rfc::H2_FRAME_PING, 0x6, "0x6 is Ping");
        sub.assert_eq(rfc::H2_FRAME_GOAWAY, 0x7, "0x7 is GoAway");
        sub.assert_eq(rfc::H2_FRAME_WINDOW_UPDATE, 0x8, "0x8 is WindowUpdate");
        sub.assert_eq(rfc::H2_FRAME_CONTINUATION, 0x9, "0x9 is Continuation");
    };

    t.run("WIRE-02: 9-Byte Frame Header Decoding & Reserved Bit Masking (RFC 9113 Sec 4.1)") { sub =>
        var short_buf: u8[8] = [0; 8];
        let _, err_short = internal::parse_frame_header(short_buf[..]);
        sub.assert_eq(err_short, rfc::H2_ERR_FRAME_SIZE_ERROR, "short header returns FrameSizeError");

        var data_hdr_raw: u8[9] = [
            0x00, 0x00, 0x80, // length = 128
            0x00,             // type = DATA
            0x01,             // flags = END_STREAM
            0x00, 0x00, 0x00, 0x05, // stream ID = 5
        ];
        let h1, err1 = internal::parse_frame_header(data_hdr_raw[..]);
        sub.assert_eq(err1, rfc::H2_ERR_NO_ERROR, "valid DATA header returns NoError");
        sub.assert_eq(h1.length, 128, "payload len is 128");
        sub.assert_eq(h1.frame_type, rfc::H2_FRAME_DATA, "frame type is Data");
        sub.assert_eq(h1.flags, 0x01, "flags match");
        sub.assert_eq(h1.stream_id, 5, "stream id is 5");

        var res_hdr_raw: u8[9] = [
            0x00, 0x01, 0x00, // length = 256
            0x01,             // type = HEADERS
            0x04,             // flags = END_HEADERS
            0x80, 0x00, 0x00, 0x03, // stream ID = 3 with high bit set
        ];
        let h2, err2 = internal::parse_frame_header(res_hdr_raw[..]);
        sub.assert_eq(err2, rfc::H2_ERR_NO_ERROR, "reserved bit header returns NoError");
        sub.assert_eq(h2.stream_id, 3, "reserved bit masked out to stream id 3");
        sub.assert_eq(h2.length, 256, "payload len is 256");
    };
}

// --- Component: http2_fsm_continuation ---
// Hardening & Security Invariants Suite for HTTP/2 Connection State Machine (RFC 9113):
// 1. SETTINGS & PING frame invariants (length % 6 == 0, ACK length == 0, Stream 0 binding).
// 2. Flow control window arithmetic, 31-bit overflow guards, and zero-increment bans.
// 3. CONTINUATION flood defense (CVE-2024-27983) and illegal frame interleaving bans.

// ----------------------------------------------------------------------------
// 16. SETTINGS & PING Frame Wire Invariants (RFC 9113 §6.5/§6.7)
// ----------------------------------------------------------------------------
fn test_h2_settings_and_ping_invariants(t: lit::T&) {
    t.run("H2-SEC-01: SETTINGS ACK with Non-Zero Length must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr = internal::FrameHeader {
            length:     6, // Length != 0 with ACK is illegal per RFC 9113 §6.5
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      rfc::H2_FLAG_ACK,
            stream_id:  0,
        };
        let err = internal::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, rfc::H2_ERR_FRAME_SIZE_ERROR, "SETTINGS with ACK and length > 0 must trigger FRAME_SIZE_ERROR");
    };

    t.run("H2-SEC-02: SETTINGS with Length not multiple of 6 must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr = internal::FrameHeader {
            length:     5, // Not multiple of 6
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0,
            stream_id:  0,
        };
        let err = internal::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, rfc::H2_ERR_FRAME_SIZE_ERROR, "SETTINGS length not multiple of 6 must trigger FRAME_SIZE_ERROR");
    };

    t.run("H2-SEC-03: SETTINGS or PING on Stream != 0 must trigger PROTOCOL_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);

        // SETTINGS on stream 1
        let hdr_set = internal::FrameHeader {
            length:     6,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0,
            stream_id:  1, // Illegal: MUST be stream 0 per RFC 9113 §6.5
        };
        let err_set = internal::on_ingress_frame_header(conn, hdr_set, 0);
        sub.assert_eq(err_set, rfc::H2_ERR_PROTOCOL_ERROR, "SETTINGS on stream != 0 must trigger PROTOCOL_ERROR");

        // PING on stream 1
        let hdr_ping = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  1, // Illegal: MUST be stream 0 per RFC 9113 §6.7
        };
        let err_ping = internal::on_ingress_frame_header(conn, hdr_ping, 0);
        sub.assert_eq(err_ping, rfc::H2_ERR_PROTOCOL_ERROR, "PING on stream != 0 must trigger PROTOCOL_ERROR");
    };

    t.run("H2-SEC-04: PING with Length != 8 must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr = internal::FrameHeader {
            length:     7, // Illegal: MUST be exactly 8 per RFC 9113 §6.7
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        let err = internal::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, rfc::H2_ERR_FRAME_SIZE_ERROR, "PING with length != 8 must trigger FRAME_SIZE_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 17. Flow Control Window Arithmetic & Overflow Guards (RFC 9113 §6.9)
// ----------------------------------------------------------------------------
fn test_h2_window_update_and_flow_control(t: lit::T&) {
    t.run("H2-SEC-05: WINDOW_UPDATE Increment 0 is Forbidden (RFC 9113 §6.9)") { sub =>
        var conn = internal::new_h2_connection(0);
        let err_conn = internal::apply_window_update(conn, 0, 0);
        sub.assert_eq(err_conn, rfc::H2_ERR_PROTOCOL_ERROR, "WINDOW_UPDATE with increment 0 on connection must trigger PROTOCOL_ERROR");

        let err_str = internal::apply_window_update(conn, 1, 0);
        sub.assert_eq(err_str, rfc::H2_ERR_PROTOCOL_ERROR, "WINDOW_UPDATE with increment 0 on stream must trigger PROTOCOL_ERROR");
    };

    t.run("H2-SEC-06: Connection Window Overflow beyond 2^31 - 1 triggers FLOW_CONTROL_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        // Default conn_send_window is 65535
        // Adding 0x7FFFFFFF will overflow MAX_INITIAL_WINDOW_SIZE (0x7FFFFFFF)
        let err = internal::apply_window_update(conn, 0, 0x7FFFFFFF);
        sub.assert_eq(err, rfc::H2_ERR_FLOW_CONTROL_ERROR, "Connection window overflow must trigger FLOW_CONTROL_ERROR");
    };

    t.run("H2-SEC-07: Excessive Initial Window Updates Flood Defense (CVE-2026-78669)") { sub =>
        var conn = internal::new_h2_connection(0);
        var hit_flood = false;
        for _ in 20 {
            let err = internal::apply_peer_initial_window_size_delta(conn, 65535);
            if err == rfc::H2_ERR_ENHANCE_YOUR_CALM {
                hit_flood = true;
                break;
            }
        }
        sub.assert_true(hit_flood, "Repeated initial window size delta flood must trigger ENHANCE_YOUR_CALM");
    };
}

// ----------------------------------------------------------------------------
// 18. CONTINUATION Flood & Interleaving Defenses (RFC 9113 §4.3/§6.10)
// ----------------------------------------------------------------------------
fn test_h2_continuation_flood_and_interleaving(t: lit::T&) {
    t.run("H2-SEC-08: Interleaved Frame During Continuation Sequence Forbidden (RFC 9113 §4.3)") { sub =>
        var conn = internal::new_h2_connection(0);

        // 1. Initial HEADERS frame on stream 1 without END_HEADERS flag
        let h_hdr = internal::FrameHeader {
            length:     100,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0, // FLAG_END_HEADERS not set
            stream_id:  1,
        };
        let err_h = internal::on_ingress_frame_header(conn, h_hdr, 0);
        sub.assert_eq(err_h, rfc::H2_ERR_NO_ERROR, "HEADERS frame enters continuation state cleanly");
        sub.assert_eq(conn.continuation_stream_id, 1, "connection expects continuation on stream 1");

        // 2. Interleaved PING frame on stream 0 arrives before CONTINUATION
        let ping_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        let err_ping = internal::on_ingress_frame_header(conn, ping_hdr, 0);
        sub.assert_eq(err_ping, rfc::H2_ERR_PROTOCOL_ERROR, "Interleaved PING during continuation sequence must trigger PROTOCOL_ERROR per RFC 9113 §4.3");

        // 3. Interleaved DATA on stream 1 arrives before CONTINUATION
        let data_hdr = internal::FrameHeader {
            length:     50,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      0,
            stream_id:  1,
        };
        let err_data = internal::on_ingress_frame_header(conn, data_hdr, 0);
        sub.assert_eq(err_data, rfc::H2_ERR_PROTOCOL_ERROR, "Interleaved DATA during continuation sequence must trigger PROTOCOL_ERROR per RFC 9113 §4.3");
    };

    t.run("H2-SEC-09: CONTINUATION on Different Stream ID Rejected (RFC 9113 §6.10)") { sub =>
        var conn = internal::new_h2_connection(0);

        // HEADERS on stream 3 without END_HEADERS
        let h_hdr = internal::FrameHeader {
            length:     50,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0,
            stream_id:  3,
        };
        let _ = internal::on_ingress_frame_header(conn, h_hdr, 0);

        // CONTINUATION arrives on stream 5 instead of 3
        let cont_hdr = internal::FrameHeader {
            length:     50,
            frame_type: rfc::H2_FRAME_CONTINUATION,
            flags:      0,
            stream_id:  5,
        };
        let err_cont = internal::on_ingress_frame_header(conn, cont_hdr, 0);
        sub.assert_eq(err_cont, rfc::H2_ERR_PROTOCOL_ERROR, "CONTINUATION on different stream ID must trigger PROTOCOL_ERROR per RFC 9113 §6.10");
    };
}

// --- Component: http2_hpack_invariants ---
// Hardening & Security Invariants Suite for HPACK / RFC 7541 and RFC 9113:
// 1. Shift overflow & 31-bit integer boundary attacks (FIND-401).
// 2. Dynamic table LIFO index mapping, eviction to 0, and ring buffer wrap-around.
// 3. Dynamic table size update placement & bounds enforcement.
// 4. RFC 9113 pseudo-header ordering, duplicate checks, and connection header bans.

// ----------------------------------------------------------------------------
// 19. HPACK Variable-Length Integer Codec Overflows (FIND-401)
// ----------------------------------------------------------------------------
fn test_hpack_integer_codec_overflows(t: lit::T&) {
    t.run("HPACK-SEC-01: Prefix bits out of range and empty slice bounds") { sub =>
        let empty_buf: u8[0] = [];
        let _, _, ok_empty = internal::hpack_decode_int(empty_buf[..], 0, 7);
        sub.assert_false(ok_empty, "empty slice must fail integer decoding");

        let buf: u8[4] = [0xFF, 0xFF, 0xFF, 0x00];
        let _, _, ok_zero_pref = internal::hpack_decode_int(buf[..], 0, 0);
        sub.assert_false(ok_zero_pref, "prefix_bits = 0 is invalid per RFC 7541");

        let _, _, ok_nine_pref = internal::hpack_decode_int(buf[..], 0, 9);
        sub.assert_false(ok_nine_pref, "prefix_bits = 9 is invalid (> 8)");
    };

    t.run("HPACK-SEC-02: Multibyte Integer Decoding Correctness") { sub =>
        // 5-bit prefix: 31 + (26 + (10 << 7)) = 31 + 26 + 1280 = 1337
        let enc_1337: u8[3] = [0x1F, 0x9A, 0x0A];
        let val, next_off, ok = internal::hpack_decode_int(enc_1337[..], 0, 5);
        sub.assert_true(ok, "decoding 1337 succeeds");
        sub.assert_eq(val, 1337, "decoded integer matches 1337");
        sub.assert_eq(next_off, 3, "consumed 3 bytes");

        // Single-byte integer: 10 with 7-bit prefix
        let enc_single: u8[1] = [0x0A];
        let val_s, off_s, ok_s = internal::hpack_decode_int(enc_single[..], 0, 7);
        sub.assert_true(ok_s, "single-byte decode succeeds");
        sub.assert_eq(val_s, 10, "decoded value is 10");
        sub.assert_eq(off_s, 1, "consumed 1 byte");
    };

    t.run("HPACK-SEC-03: Truncated Continuation Sequence Detection") { sub =>
        // 7-bit prefix is 127 (0x7F), followed by 0x80 (continuation bit set) but stream ends
        let truncated: u8[2] = [0x7F, 0x80];
        let _, _, ok_trunc = internal::hpack_decode_int(truncated[..], 0, 7);
        sub.assert_false(ok_trunc, "truncated continuation must return false");
    };

    t.run("HPACK-SEC-04: Integer Shift Overflow Protection (FIND-401)") { sub =>
        // 10 continuation bytes of 0xFF (shift would exceed 28 and payload > 0x0F)
        let overflow_bytes: u8[11] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        let _, _, ok_ovf = internal::hpack_decode_int(overflow_bytes[..], 0, 7);
        sub.assert_false(ok_ovf, "chain of 0xFF continuation bytes must fail shift overflow");

        // Shift == 28 with payload > 0x0F (e.g. 0x10) must fail
        let overflow_28: u8[6] = [0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0x10];
        let _, _, ok_28 = internal::hpack_decode_int(overflow_28[..], 0, 7);
        sub.assert_false(ok_28, "shift 28 with payload 0x10 must fail 31-bit limit");
    };
}

// ----------------------------------------------------------------------------
// 20. HPACK Dynamic Table Invariants, Eviction & Wrap-Around
// ----------------------------------------------------------------------------
fn test_hpack_dynamic_table_invariants(t: lit::T&) {
    t.run("HPACK-SEC-05: Index 0 is strictly forbidden (RFC 7541 §6.1)") { sub =>
        let dt = internal::new_dynamic_table(4096);
        let _, _, ok_zero = internal::get_indexed_header_slices(dt, 0);
        sub.assert_false(ok_zero, "index 0 lookup must fail");
    };

    t.run("HPACK-SEC-06: Dynamic Table LIFO Order and Eviction to 0") { sub =>
        var dt = internal::new_dynamic_table(4096);
        internal::insert_header(dt, "custom-header-1", "value-1");
        internal::insert_header(dt, "custom-header-2", "value-2");

        sub.assert_eq(dt.count, 2, "2 active entries");

        // Most recent entry must be at index 62
        let n62, v62, ok62 = internal::get_indexed_header_slices(dt, 62);
        sub.assert_true(ok62, "index 62 exists");
        sub.assert_eq(n62, "custom-header-2", "index 62 is most recently added entry");
        sub.assert_eq(v62, "value-2", "index 62 value is value-2");

        // Preceding entry must be at index 63
        let n63, v63, ok63 = internal::get_indexed_header_slices(dt, 63);
        sub.assert_true(ok63, "index 63 exists");
        sub.assert_eq(n63, "custom-header-1", "index 63 is custom-header-1");

        // Out of bounds dynamic index
        let _, _, ok64 = internal::get_indexed_header_slices(dt, 64);
        sub.assert_false(ok64, "index 64 out of bounds must fail");

        // Evict until 0
        internal::evict_until(dt, 0);
        sub.assert_eq(dt.count, 0, "count is 0 after evicting to 0");
        sub.assert_eq(dt.used_bytes, 0, "used bytes is 0 after evicting to 0");

        let _, _, ok_after = internal::get_indexed_header_slices(dt, 62);
        sub.assert_false(ok_after, "lookup after evict_until(0) must fail");
    };

    t.run("HPACK-SEC-07: Dynamic Table Ring Wrap-Around without Leakage") { sub =>
        var dt = internal::new_dynamic_table(2048);
        // Insert 200 entries into 128-slot ring table
        for i in 200 {
            internal::insert_header(dt, "x-header", "x-value");
        }
        sub.assert_true(dt.count > 0, "table still holds entries");
        sub.assert_true(dt.count <= 128, "count cannot exceed 128 ring capacity");
        sub.assert_true(dt.used_bytes <= 2048, "used bytes stays within current max size");

        // Top entry must be valid
        let n_top, v_top, ok_top = internal::get_indexed_header_slices(dt, 62);
        sub.assert_true(ok_top, "top entry at 62 resolves cleanly after wrap-around");
        sub.assert_eq(n_top, "x-header", "name matches");
        sub.assert_eq(v_top, "x-value", "val matches");
    };
}

// ----------------------------------------------------------------------------
// 21. RFC 9113 Header Block Security Rules & Invariants
// ----------------------------------------------------------------------------
fn test_hpack_rfc9113_header_block_rules(t: lit::T&) {
    t.run("HPACK-SEC-08: Dynamic Table Size Update in middle of Block Rejected") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // Header block:
        // 1. Static index 2 (:method: GET) -> 0x82
        // 2. Dynamic table size update: 001xxxxx -> 0x3F 0x00 (size = 31)
        let bad_block: u8[3] = [0x82, 0x3F, 0x00];
        let err = internal::decode_hpack_to_map(dt, bad_block[..], pseudo, out_list);
        sub.assert_eq(err, rfc::H2_ERR_COMPRESSION_ERROR, "table size update after regular header must fail with COMPRESSION_ERROR per RFC 7541 §4.2");
    };

    t.run("HPACK-SEC-09: Table Size Update Exceeding SETTINGS Max Rejected") { sub =>
        var dt = internal::new_dynamic_table(1024); // max allowed size = 1024
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // Table size update requesting 2048:
        // 001xxxxx prefix 5: 0x3F (31), followed by (2048 - 31) = 2017 -> 2017 = 0x7E1 -> 0xE1 0x0F
        let oversize_block: u8[3] = [0x3F, 0xE1, 0x0F];
        let err = internal::decode_hpack_to_map(dt, oversize_block[..], pseudo, out_list);
        sub.assert_eq(err, rfc::H2_ERR_COMPRESSION_ERROR, "size update exceeding max_allowed_size must trigger COMPRESSION_ERROR");
    };

    t.run("HPACK-SEC-10: Pseudo-Header Ordering (Pseudo After Regular Rejected)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // Header block:
        // 1. Static index 24 (cache-control: no-cache) -> 0x98 (regular header)
        // 2. Static index 2 (:method: GET) -> 0x82 (pseudo-header)
        let out_of_order_block: u8[2] = [0x98, 0x82];
        let err = internal::decode_hpack_to_map(dt, out_of_order_block[..], pseudo, out_list);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "pseudo-header after regular header must trigger PROTOCOL_ERROR per RFC 9113 §8.3");
    };

    t.run("HPACK-SEC-11: Forbidden Connection Headers in HTTP/2 Rejected") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // Literal Header with Incremental Indexing (01000000 = 0x40):
        // Name: "connection" (raw, 10 bytes): 0x0A, "connection"
        // Val: "close" (raw, 5 bytes): 0x05, "close"
        var conn_block: u8[..64] = [];
        conn_block.push(0x82); // :method: GET (valid pseudo)
        conn_block.push(0x40); // Literal with indexing, new name
        conn_block.push(10);   // name len 10
        conn_block.append("connection");
        conn_block.push(5);    // val len 5
        conn_block.append("close");

        let err = internal::decode_hpack_to_map(dt, conn_block[..], pseudo, out_list);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "Connection header must trigger PROTOCOL_ERROR per RFC 9113 §8.2.2");
    };

    t.run("HPACK-SEC-12: Disallowed TE Header Value Rejected") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // TE header with value other than "trailers" (e.g. "gzip") is illegal in HTTP/2
        var te_block: u8[..64] = [];
        te_block.push(0x82); // :method: GET
        te_block.push(0x40); // Literal with indexing
        te_block.push(2);    // "te"
        te_block.append("te");
        te_block.push(4);    // "gzip"
        te_block.append("gzip");

        let err = internal::decode_hpack_to_map(dt, te_block[..], pseudo, out_list);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "TE header with value other than 'trailers' must trigger PROTOCOL_ERROR per RFC 9113 §8.2.2");
    };
}

// --- Component: http2_extended_connect ---
// Verification suite for RFC 8441 & RFC 9220: Extended CONNECT (WebSockets over H2 and H3):
// - Detection of Extended CONNECT vs classic TCP tunnel CONNECT
// - HTTP/3 client request formatting (:protocol = websocket)
// - Strict protocol invariance: rejection of Upgrade/Connection/Sec-WebSocket-Key
// - Server-side upgrade producing 200 OK and subprotocol negotiation
// - Zero-allocation stream encapsulation of masked (client) and unmasked (server) WS frames

// ----------------------------------------------------------------------------
// 22. Extended CONNECT Detection
// ----------------------------------------------------------------------------
fn test_extended_connect_detection(t: lit::T&) {
    t.run("Extended CONNECT vs Classic Tunnel Detection") { sub =>
        // 1. Classic TCP tunnel CONNECT (RFC 9114 §4.4)
        var tunnel_req = wing::new_request("CONNECT", "example.com:443");
        wing::set_header(tunnel_req, ":method", "CONNECT");
        wing::set_header(tunnel_req, ":authority", "example.com:443");
        sub.assert_false(wing::is_extended_connect_request(tunnel_req), "Classic tunnel is not extended connect");

        // 2. Extended CONNECT (RFC 8441 / RFC 9220)
        var ext_req = wing::new_request("CONNECT", "/chat");
        wing::set_header(ext_req, ":method", "CONNECT");
        wing::set_header(ext_req, ":protocol", "websocket");
        wing::set_header(ext_req, ":scheme", "https");
        wing::set_header(ext_req, ":authority", "example.com");
        wing::set_header(ext_req, ":path", "/chat");
        sub.assert_true(wing::is_extended_connect_request(ext_req), "Detected extended connect via :protocol");

        // 3. Regular GET request
        var get_req = wing::new_request("GET", "/index.html");
        sub.assert_false(wing::is_extended_connect_request(get_req), "GET is not extended connect");
    };
}

// ----------------------------------------------------------------------------
// 23. H3 WebSocket Formatting & Validation
// ----------------------------------------------------------------------------
fn test_h3_websocket_formatting(t: lit::T&) {
    t.run("HTTP/3 Request Formatting & Protocol Validation (RFC 9220 §3)") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h3_websocket_request(req, "/v2/feed", "h3.example.com", "https", "json-stream");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "/v2/feed", "URL matches");

        sub.assert_bytes_eq(req.header(":method"), "CONNECT", ":method pseudo-header is CONNECT");
        sub.assert_bytes_eq(req.header(":protocol"), "websocket", ":protocol pseudo-header is websocket");
        sub.assert_bytes_eq(req.header(":scheme"), "https", ":scheme pseudo-header is https");
        sub.assert_bytes_eq(req.header(":authority"), "h3.example.com", ":authority matches");
        sub.assert_bytes_eq(req.header(":path"), "/v2/feed", ":path matches");
        sub.assert_bytes_eq(req.header("sec-websocket-version"), "13", "Version is 13");
        sub.assert_bytes_eq(req.header("sec-websocket-protocol"), "json-stream", "Subprotocol matches");

        sub.assert_true(wing::validate_h3_websocket_request(req), "Valid RFC 9220 request passes");

        // Strict rejection of forbidden headers (RFC 9220 §3)
        var bad_req = req;
        wing::set_header(bad_req, "Upgrade", "websocket");
        sub.assert_false(wing::validate_h3_websocket_request(bad_req), "Upgrade header rejected");

        var bad_req2 = req;
        wing::set_header(bad_req2, "Sec-WebSocket-Key", "abc123==");
        sub.assert_false(wing::validate_h3_websocket_request(bad_req2), "Sec-WebSocket-Key rejected");
    };
}

// ----------------------------------------------------------------------------
// 24. H3 Server Upgrade (200 OK)
// ----------------------------------------------------------------------------
fn test_h3_server_upgrade(t: lit::T&) {
    t.run("Server-Side HTTP/3 WebSocket Upgrade (200 OK)") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h3_websocket_request(req, "/ws", "h3.example.com", "https", "v1.proto, v2.proto");

        var resp = wing::Response { .. };
        let session, ok = wing::ws_h3_upgrade_request(req, resp, "v2.proto");
        sub.assert_true(ok, "Upgrade accepted");
        sub.assert_eq(resp.status_code, 200, "RFC 9220 §3: Status code MUST be 200 (NOT 101)");
        sub.assert_bytes_eq(resp.header("sec-websocket-protocol"), "v2.proto", "Negotiated subprotocol matches");
        sub.assert_bytes_eq(session.subprotocol[..], "v2.proto", "Session records negotiated subprotocol");
        sub.assert_true(wing::is_h3_websocket_response(resp), "Response identified as H3 WebSocket acceptance");
    };
}

// ----------------------------------------------------------------------------
// 25. Stream Frame Encapsulation
// ----------------------------------------------------------------------------
fn test_stream_frame_encapsulation(t: lit::T&) {
    t.run("Stream Encapsulation of Masked and Unmasked Frames") { sub =>
        // 1. Client frame (MUST be masked)
        var client_data: u8[>..] = [];
        let mask: const u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        wing::ws_encapsulate_stream_data(client_data, rfc::WS_OPCODE_TEXT, "Hello H3 WebSocket", true, mask);

        let hdr_c, ok_c = wing::parse_ws_frame_header(client_data[..]);
        sub.assert_true(ok_c, "Client frame header parsed");
        sub.assert_true(hdr_c.masked, "Client frame has mask bit set");
        sub.assert_eq(hdr_c.opcode, rfc::WS_OPCODE_TEXT, "Opcode is TEXT");

        // 2. Server frame (MUST NOT be masked per RFC 6455 §5.1 / RFC 8441 / RFC 9220)
        var server_data: u8[>..] = [];
        wing::ws_encapsulate_stream_data(server_data, rfc::WS_OPCODE_TEXT, "Server response payload", false);

        let hdr_s, ok_s = wing::parse_ws_frame_header(server_data[..]);
        sub.assert_true(ok_s, "Server frame header parsed");
        sub.assert_false(hdr_s.masked, "Server frame MUST NOT be masked");
        sub.assert_eq(hdr_s.payload_len as i64, ("Server response payload").len, "Payload length matches");
    };
}

// --- Component: http2_priority_rfc9218 ---
// Verification suite for RFC 9218 Extensible HTTP Priority:
// - Structured Field priority header parsing (u=0..7, i=?1/?0)
// - Unknown parameter tolerance per RFC 9218 Section 4
// - Priority header canonical serialization
// - HTTP/2 PRIORITY_UPDATE frame encoding, decoding, and validation
// - HTTP/3 PRIORITY_UPDATE frame processing and connection state update

// ----------------------------------------------------------------------------
// 26. Priority Parsing
// ----------------------------------------------------------------------------
fn test_priority_parsing(t: lit::T&) {
    t.run("Priority Header Parsing (RFC 9218 §4)") { sub =>
        // 1. High urgency with incremental
        let p1, ok1 = wing::parse_http_priority("u=0, i");
        sub.assert_true(ok1, "Parsed u=0, i");
        sub.assert_eq(p1.urgency, 0, "Urgency 0");
        sub.assert_true(p1.incremental, "Incremental true");

        // 2. Lowest urgency without incremental
        let p2, ok2 = wing::parse_http_priority("u=7");
        sub.assert_true(ok2, "Parsed u=7");
        sub.assert_eq(p2.urgency, 7, "Urgency 7");
        sub.assert_false(p2.incremental, "Incremental false");

        // 3. Incremental only (urgency defaults to 3)
        let p3, ok3 = wing::parse_http_priority("i");
        sub.assert_true(ok3, "Parsed i");
        sub.assert_eq(p3.urgency, 3, "Default urgency 3");
        sub.assert_true(p3.incremental, "Incremental true");

        // 4. Reverse order with explicit boolean ?0
        let p4, ok4 = wing::parse_http_priority("i=?0, u=2");
        sub.assert_true(ok4, "Parsed i=?0, u=2");
        sub.assert_eq(p4.urgency, 2, "Urgency 2");
        sub.assert_false(p4.incremental, "Incremental false");

        // 5. Unknown parameter tolerance (RFC 9218 §4)
        let p5, ok5 = wing::parse_http_priority("u=1, unknown=param, i");
        sub.assert_true(ok5, "Parsed with unknown parameter");
        sub.assert_eq(p5.urgency, 1, "Urgency 1");
        sub.assert_true(p5.incremental, "Incremental true");

        // 6. Out of range urgency ignored (must stay default 3)
        let p6, ok6 = wing::parse_http_priority("u=9, i");
        sub.assert_true(ok6, "Parsed with out-of-range u");
        sub.assert_eq(p6.urgency, 3, "Urgency preserved default 3");
        sub.assert_true(p6.incremental, "Incremental true");

        // 7. Standalone out-of-range u=8 or unknown key foo=1 succeeds with defaults (RFC 9218 §4)
        let p7, ok7 = wing::parse_http_priority("u=8");
        sub.assert_true(ok7, "Standalone out-of-range u=8 ignored with defaults");
        sub.assert_eq(p7.urgency, 3, "Standalone u=8 defaults urgency to 3");
        sub.assert_false(p7.incremental, "Standalone u=8 defaults incremental to false");
        let p8, ok8 = wing::parse_http_priority("foo=1");
        sub.assert_true(ok8, "Unknown-only SF dictionary key ignored with defaults");
        sub.assert_eq(p8.urgency, 3, "Unknown-only key defaults urgency to 3");
    };
}

// ----------------------------------------------------------------------------
// 27. Priority Serialization
// ----------------------------------------------------------------------------
fn test_priority_serialization(t: lit::T&) {
    t.run("Priority Header Serialization") { sub =>
        var out: u8[>..] = [];

        var p1 = wing::PriorityParam { urgency: 0, incremental: true };
        wing::serialize_http_priority(p1, out);
        sub.assert_eq(out[..], "u=0, i", "Serialized u=0, i");

        out.clear();
        var p2 = wing::PriorityParam { urgency: 5, incremental: false };
        wing::serialize_http_priority(p2, out);
        sub.assert_eq(out[..], "u=5", "Serialized u=5");

        let def_p = wing::priority_default();
        sub.assert_true(wing::priority_is_default(def_p), "Default priority recognized");
        sub.assert_false(wing::priority_is_default(p1), "Non-default priority recognized");
    };
}

// ----------------------------------------------------------------------------
// 28. H2 Priority Update Frame
// ----------------------------------------------------------------------------
fn test_h2_priority_update_frame(t: lit::T&) {
    t.run("HTTP/2 PRIORITY_UPDATE Frame (RFC 9218 §7.1)") { sub =>
        var frame_buf: u8[>..] = [];
        let prio = wing::PriorityParam { urgency: 1, incremental: true };
        internal::encode_priority_update_payload(5, prio, frame_buf);

        sub.assert_gt(frame_buf.len, 4, "Frame payload encoded");

        let stream_id, parsed_prio, err = internal::parse_priority_update_payload(frame_buf[..]);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "No protocol error");
        sub.assert_eq(stream_id, 5, "Stream ID matches 5");
        sub.assert_eq(parsed_prio.urgency, 1, "Urgency matches 1");
        sub.assert_true(parsed_prio.incremental, "Incremental matches true");

        // Stream ID 0 rejection (RFC 9218 §7.1)
        var zero_id_buf: u8[8] = [0, 0, 0, 0, 'u' as u8, '=' as u8, '2' as u8, 0];
        let _, _, err_zero = internal::parse_priority_update_payload(zero_id_buf[..]);
        sub.assert_eq(err_zero, rfc::H2_ERR_PROTOCOL_ERROR, "Stream 0 rejected with PROTOCOL_ERROR");

        // Truncated payload (< 4 bytes)
        var trunc_buf: u8[2] = [0, 1];
        let _, _, err_trunc = internal::parse_priority_update_payload(trunc_buf[..]);
        sub.assert_eq(err_trunc, rfc::H2_ERR_FRAME_SIZE_ERROR, "Truncated frame rejected with FRAME_SIZE_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 29. H3 Priority Update Integration
// ----------------------------------------------------------------------------
fn test_h3_priority_update_integration(t: lit::T&) {
    t.run("HTTP/3 PRIORITY_UPDATE Control Frame (RFC 9218 §7.2)") { sub =>
        // Create an H3Connection with a request stream
        var conn = internal::H3Connection { .. };
        conn.role = internal::H3ConnRole.Server;
        conn.state = internal::H3ConnState.Active;
        let req_id, ok_req = internal::open_request_stream(conn);
        sub.assert_true(ok_req, "Created request stream");

        // Verify initial priority is default u=3, i=false
        let init_prio, ok_init = internal::get_stream_priority(conn, req_id);
        sub.assert_true(ok_init, "Initial priority retrieved");
        sub.assert_eq(init_prio.urgency, 3, "Initial urgency 3");
        sub.assert_false(init_prio.incremental, "Initial incremental false");

        // Encode a PRIORITY_UPDATE frame for stream 0
        var update_buf: u8[>..] = [];
        let new_prio = wing::PriorityParam { urgency: 0, incremental: true };
        let enc_ok = internal::encode_h3_priority_update_request(update_buf, req_id, new_prio);
        sub.assert_true(enc_ok, "Encoded H3 PRIORITY_UPDATE frame");

        // Deliver control stream type 0x00 and SETTINGS frame to initialize control stream
        conn.peer_control_stream_id = 3;
        var init_ctrl: u8[>..] = [];
        init_ctrl.push(0x00 as u8); // Control stream type
        var settings = wing::H3Settings { .. };
        internal::encode_h3_settings_frame(init_ctrl, settings);
        let err_init = internal::handle_stream_data(conn, 3, false, init_ctrl[..], false);
        sub.assert_eq(err_init, rfc::H3_ERR_NO_ERROR, "Control stream initialized");

        // Now deliver PRIORITY_UPDATE frame on unidirectional stream 3
        let err_pu = internal::handle_stream_data(conn, 3, false, update_buf[..], false);
        sub.assert_eq(err_pu, rfc::H3_ERR_NO_ERROR, "PRIORITY_UPDATE handled cleanly");

        // Verify that stream 0 priority has been dynamically updated!
        let updated_prio, ok_up = internal::get_stream_priority(conn, req_id);
        sub.assert_true(ok_up, "Updated priority retrieved");
        sub.assert_eq(updated_prio.urgency, 0, "Urgency dynamically updated to 0");
        sub.assert_true(updated_prio.incremental, "Incremental dynamically updated to true");
    };
}

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame
// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame
// ----------------------------------------------------------------------------
// 30. HTTP/2 FRAME_ORIGIN & FRAME_ALTSVC (RFC 8336 & RFC 7838)
// ----------------------------------------------------------------------------
fn test_h2_extension_frames(t: lit::T&) {
    t.run("ORIGIN-01: FRAME_ORIGIN serialization and multi-origin parsing") { sub =>
        var origins: const u8[:][..16] = [];
        origins.push("https://example.com");
        origins.push("https://api.example.com");

        var wire: u8[>..] = [];
        let enc_ok = internal::encode_origin_frame(wire, origins);
        sub.assert_true(enc_ok, "encode_origin_frame succeeded");

        // Parse 9-byte header
        let hdr, hdr_err = internal::parse_frame_header(wire[..9]);
        sub.assert_eq(hdr_err, rfc::H2_ERR_NO_ERROR, "frame header parsed without error");
        sub.assert_eq(hdr.frame_type, rfc::H2_FRAME_ORIGIN, "frame type is FRAME_ORIGIN (0x0C)");
        sub.assert_eq(hdr.stream_id, 0, "stream id is 0");

        // Parse payload
        var parsed_origins: const u8[:][..16] = [];
        let count, parse_err = internal::parse_origin_frame(wire[9..9 + hdr.length], hdr.stream_id, parsed_origins);
        sub.assert_eq(parse_err, rfc::H2_ERR_NO_ERROR, "payload parsed without error");
        sub.assert_eq(count, 2, "parsed 2 origins");
        sub.assert_eq(parsed_origins[0], "https://example.com", "origin 0 matched");
        sub.assert_eq(parsed_origins[1], "https://api.example.com", "origin 1 matched");
    };

    t.run("ORIGIN-02: Stream ID != 0 is ignored without error (RFC 8336 Section 2.2)") { sub =>
        let dummy_payload: u8[16] = [
            0x00, 0x0E,
            'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'x', '.', 'c', 'o', 'm',
        ];
        var parsed: const u8[:][..16] = [];
        let count, err = internal::parse_origin_frame(dummy_payload[..], 1, parsed);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "ORIGIN frame on stream 1 is ignored with NO_ERROR");
        sub.assert_eq(count, 0, "ORIGIN frame on stream 1 adds 0 entries");
        sub.assert_eq(parsed.len, 0, "out_entries untouched on non-zero stream");

        let non_zero_hdr = internal::FrameHeader {
            length:     16,
            frame_type: rfc::H2_FRAME_ORIGIN,
            flags:      0,
            stream_id:  3,
        };
        let rule_err = internal::validate_frame_header_rules(non_zero_hdr);
        sub.assert_eq(rule_err, rfc::H2_ERR_NO_ERROR, "validate_frame_header_rules permits ORIGIN header on stream 3 to be ignored");
    };

    t.run("ALTSVC-01: FRAME_ALTSVC on stream 0 with origin") { sub =>
        var wire: u8[>..] = [];
        let enc_ok = internal::encode_altsvc_frame(wire, "example.com", "h3=\":443\"; ma=86400", 0);
        sub.assert_true(enc_ok, "encode_altsvc_frame succeeded");

        let hdr, hdr_err = internal::parse_frame_header(wire[..9]);
        sub.assert_eq(hdr_err, rfc::H2_ERR_NO_ERROR, "header parsed ok");
        sub.assert_eq(hdr.frame_type, rfc::H2_FRAME_ALTSVC, "frame type is FRAME_ALTSVC (0x0A)");
        sub.assert_eq(hdr.stream_id, 0, "stream id is 0");

        let altsvc, parse_err = internal::parse_altsvc_frame(wire[9..9 + hdr.length], hdr.stream_id);
        sub.assert_eq(parse_err, rfc::H2_ERR_NO_ERROR, "parsed without error");
        sub.assert_eq(altsvc.origin, "example.com", "origin matched");
        sub.assert_eq(altsvc.alt_svc_value, "h3=\":443\"; ma=86400", "alt_svc_value matched");
    };

    t.run("ALTSVC-02: FRAME_ALTSVC on stream > 0 with implicit origin") { sub =>
        var wire: u8[>..] = [];
        let enc_ok = internal::encode_altsvc_frame(wire, "", "h3=\":443\"", 5);
        sub.assert_true(enc_ok, "encode_altsvc_frame succeeded on stream 5");

        let hdr, _ = internal::parse_frame_header(wire[..9]);
        sub.assert_eq(hdr.stream_id, 5, "stream id is 5");

        let altsvc, parse_err = internal::parse_altsvc_frame(wire[9..9 + hdr.length], hdr.stream_id);
        sub.assert_eq(parse_err, rfc::H2_ERR_NO_ERROR, "parsed without error");
        sub.assert_eq(altsvc.origin.len, 0, "origin is empty on stream > 0");
        sub.assert_eq(altsvc.alt_svc_value, "h3=\":443\"", "alt_svc_value matched");
    };

    t.run("ALTSVC-03: Empty origin on stream 0 is ignored per RFC 7838 §4") { sub =>
        let payload: u8[6] = [0x00, 0x00, 'h', '3', '=', '1'];
        let altsvc, err = internal::parse_altsvc_frame(payload[..], 0);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "empty origin on stream 0 is ignored");
        sub.assert_eq(altsvc.alt_svc_value.len, 0, "ignored frame has empty value");
    };

    t.run("ALTSVC-04: Non-zero origin on stream > 0 is ignored per RFC 7838 §4") { sub =>
        let payload: u8[8] = [0x00, 0x02, 'o', 'k', 'h', '3', '=', '1'];
        let altsvc, err = internal::parse_altsvc_frame(payload[..], 1);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "non-empty origin on stream 1 is ignored");
        sub.assert_eq(altsvc.alt_svc_value.len, 0, "ignored frame has empty value");
    };

    t.run("ALTSVC-05: Server Ingress handles ORIGIN and ALTSVC extension frames") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(rfc::H2_CLIENT_PREFACE[..]);

        var origins: const u8[:][..16] = [];
        origins.push("https://example.com");
        internal::encode_origin_frame(wire, origins);
        internal::encode_altsvc_frame(wire, "example.com", "h3=\":443\"", 0);

        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);
        sub.assert_true(ok, "handle_h2_server_ingress processed ORIGIN and ALTSVC extension frames");
        sub.assert_eq(consumed, wire.len, "Consumed entire client stream with extensions");
    };
}

// --- Component: nghttp2_and_h2_vendor_conformance ---
// Ported test vectors from vendor/nghttp2 (tests/nghttp2_hd_test.c,
// tests/nghttp2_frame_test.c, tests/nghttp2_http_test.c) and vendor/h2:
// - HPACK zero-length Huffman string literal ([0x40, 0x01, 'x', 0x80] -> x: "")
// - HPACK indexed representation 0x80 (index == 0) rejection
// - HPACK dynamic table shrink to 0 (0x20) followed by resize to 1024 (0x3F, 0xE1, 0x07)
// - HPACK 150-entry sequential insertion & FIFO wrap-around verification
// - RFC 9218 Extensible Priority dictionary edge cases from test_nghttp2_http_parse_priority
// - RST_STREAM arbitrary 32-bit error code (1000000009) & HEADERS FLAG_PRIORITY bitmask
// ----------------------------------------------------------------------------
// 31. nghttp2 & h2 Vendor Conformance Vectors
// ----------------------------------------------------------------------------
fn test_nghttp2_and_h2_vendor_conformance(t: lit::T&) {
    t.run("NGHTTP2-HD-01: Zero-length Huffman literal and empty value encoding/decoding") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Request pseudo-headers + literal with incremental indexing (0x40), name "x" (len 1),
        // value: Huffman bit set with length 0 (0x80)
        let wire: u8[7] = [0x82, 0x87, 0x84, 0x40, 0x01, 'x', 0x80];
        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, wire[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "zero-length Huffman string literal decodes with NO_ERROR");
        sub.assert_true(out.has_header("x"), "header 'x' present in decoded map");
        sub.assert_eq(out.get_header("x"), "", "header 'x' has empty value");
        sub.assert_eq(dt.count, 1, "entry inserted into dynamic table");
    };

    t.run("NGHTTP2-HD-02: Indexed representation 0x80 (index 0) and out-of-bounds static/dynamic indices") { sub =>
        var dt = internal::new_dynamic_table(4096);
        let wire_idx0: u8[1] = [0x80];
        var pseudo0 = internal::H2PseudoHeaders { .. };
        var out0 = wing::HeaderMap { .. };
        let err0 = internal::decode_hpack_to_map(dt, wire_idx0[..], pseudo0, out0);
        sub.assert_eq(err0, rfc::H2_ERR_COMPRESSION_ERROR, "indexed representation 0x80 must return COMPRESSION_ERROR");

        // Index 62 when dynamic table is empty -> COMPRESSION_ERROR
        let wire_idx62: u8[2] = [0x82, 0xBE];
        var pseudo62 = internal::H2PseudoHeaders { .. };
        var out62 = wing::HeaderMap { .. };
        let err62 = internal::decode_hpack_to_map(dt, wire_idx62[..], pseudo62, out62);
        sub.assert_eq(err62, rfc::H2_ERR_COMPRESSION_ERROR, "out-of-bounds dynamic index 62 on empty table returns COMPRESSION_ERROR");
    };

    t.run("NGHTTP2-HD-03: Dynamic Table Size Update 0 Eviction + Resize to 1024 (RFC 7541 §4.2)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        internal::insert_header(dt, "x-nghttp2-a", "alpha");
        internal::insert_header(dt, "x-nghttp2-b", "bravo");
        sub.assert_eq(dt.count, 2, "2 entries before size update");

        // Header block starting with two consecutive table size updates:
        // 1. 0x20 (size = 0 -> evicts all entries)
        // 2. 0x3F, 0xE1, 0x07 (size = 31 + 0x61 + (7 << 7) = 31 + 97 + 896 = 1024)
        // Followed by :method: GET (0x82), :scheme: https (0x87), :path: / (0x84)
        let wire: u8[7] = [0x20, 0x3F, 0xE1, 0x07, 0x82, 0x87, 0x84];
        var pseudo = internal::H2PseudoHeaders { .. };
        var out = wing::HeaderMap { .. };
        let err = internal::decode_hpack_to_map(dt, wire[..], pseudo, out);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "consecutive leading table size updates (0 then 1024) accepted");
        sub.assert_eq(dt.count, 0, "size update to 0 evicted all prior dynamic entries");
        sub.assert_eq(dt.used_bytes, 0, "used_bytes is 0 after eviction");
        sub.assert_eq(dt.current_max_size, 1024, "current_max_size updated to 1024");
    };

    t.run("NGHTTP2-HD-04: 150-Iteration HPACK Encode/Decode Ring Buffer Wrap-Around") { sub =>
        var enc_dt = internal::new_dynamic_table(4096);
        var dec_dt = internal::new_dynamic_table(4096);

        var i: u32 = 0;
        while i < 150 {
            var hblock: u8[..128] = [];
            hblock.push(0x82); // :method GET
            hblock.push(0x87); // :scheme https
            hblock.push(0x84); // :path /

            var val_buf: u8[..16] = [];
            val_buf.append("val-");
            val_buf.push(('0' + ((i / 100) % 10) as u8));
            val_buf.push(('0' + ((i / 10) % 10) as u8));
            val_buf.push(('0' + (i % 10) as u8));

            internal::encode_hpack_field(enc_dt, hblock, "x-seq-id", val_buf[..], internal::HpackIndexing.Incremental, true);

            var pseudo = internal::H2PseudoHeaders { .. };
            var out = wing::HeaderMap { .. };
            let err = internal::decode_hpack_to_map(dec_dt, hblock[..], pseudo, out);
            sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "iteration HPACK block decoded");
            sub.assert_eq(out.get_header("x-seq-id"), val_buf[..], "decoded x-seq-id matches encoded value");
            i += 1;
        }
        sub.assert_eq(enc_dt.count, dec_dt.count, "encoder and decoder dynamic table counts stay in lockstep");
        sub.assert_eq(enc_dt.used_bytes, dec_dt.used_bytes, "encoder and decoder used_bytes stay in lockstep");
    };

    t.run("NGHTTP2-HTTP-01: RFC 9218 Extensible Priority Vectors (test_nghttp2_http_parse_priority)") { sub =>
        // 1. Empty string -> returns default urgency=3, inc=false with ok=false (no explicit parameter)
        let p_empty, ok_empty = wing::parse_http_priority("");
        sub.assert_false(ok_empty, "empty priority field has no explicit parameters");
        sub.assert_eq(p_empty.urgency, 3, "default urgency 3");
        sub.assert_false(p_empty.incremental, "default incremental false");

        // 2. "u=7,i" -> urgency=7, inc=true
        let p1, ok1 = wing::parse_http_priority("u=7,i");
        sub.assert_true(ok1, "u=7,i parses");
        sub.assert_eq(p1.urgency, 7, "urgency 7");
        sub.assert_true(p1.incremental, "incremental true");

        // 3. "u=0,i=?0" -> urgency=0, inc=false
        let p2, ok2 = wing::parse_http_priority("u=0,i=?0");
        sub.assert_true(ok2, "u=0,i=?0 parses");
        sub.assert_eq(p2.urgency, 0, "urgency 0");
        sub.assert_false(p2.incremental, "incremental false");

        // 4. Duplicate keys: "u=0, i, i=?0, u=6" -> last key wins (urgency=6, inc=false)
        let p3, ok3 = wing::parse_http_priority("u=0, i, i=?0, u=6");
        sub.assert_true(ok3, "duplicate keys parse");
        sub.assert_eq(p3.urgency, 6, "later urgency u=6 overwrites u=0");
        sub.assert_false(p3.incremental, "later i=?0 overwrites i");

        // 5. Explicit boolean ?1: "i=?1" -> urgency=3, inc=true
        let p4, ok4 = wing::parse_http_priority("i=?1");
        sub.assert_true(ok4, "i=?1 parses");
        sub.assert_eq(p4.urgency, 3, "default urgency 3");
        sub.assert_true(p4.incremental, "incremental true");

        // 6. Out-of-bounds u=-1 or u=8 ignored/preserved per RFC 9218 §4
        let p5, ok5 = wing::parse_http_priority("u=-1, i=?1");
        sub.assert_true(ok5, "u=-1 ignored gracefully");
        sub.assert_eq(p5.urgency, 3, "urgency remains default 3");
        sub.assert_true(p5.incremental, "incremental true preserved");

        // 7. Complex parameterized dictionary with inner list and quoted commas (nghttp2_http_test.c:249)
        let p6, ok6 = wing::parse_http_priority("i=?0, u=1, a=(x y z), u=2; i=?0;foo=\",,,\", i=?1;i=?0; u=6");
        sub.assert_true(ok6, "complex parameterized priority dictionary parses");
        sub.assert_eq(p6.urgency, 2, "u=2 wins (u=6 after ';' is parameter on i, not dict member)");
        sub.assert_true(p6.incremental, "i=?1 wins (i=?0 after ';' is parameter, not dict member)");

        // 8. RFC 9218 §4: Values of unexpected types MUST be ignored, malformed SF rejected
        let p_bad_i, ok_bad_i = wing::parse_http_priority("i=(1 2), u=1");
        sub.assert_true(ok_bad_i, "inner list i=(1 2) ignored per RFC 9218 §4");
        sub.assert_eq(p_bad_i.urgency, 1, "u=1 still applied after ignored i=(1 2)");
        sub.assert_false(p_bad_i.incremental, "default incremental preserved when i=(1 2) ignored");
        let p_bad_u, ok_bad_u = wing::parse_http_priority("u=(1 2), i");
        sub.assert_true(ok_bad_u, "inner list u=(1 2) ignored per RFC 9218 §4");
        sub.assert_eq(p_bad_u.urgency, 3, "default urgency 3 preserved when u=(1 2) ignored");
        sub.assert_true(p_bad_u.incremental, "i still applied after ignored u=(1 2)");
        let _, ok_bad_syntax = wing::parse_http_priority("u=0,");
        sub.assert_false(ok_bad_syntax, "trailing comma 'u=0,' rejected");
    };

    t.run("NGHTTP2-FRAME-01: RST_STREAM with Unknown Error Code & HEADERS Exclusive Priority Bit") { sub =>
        // nghttp2_frame_test.c: test_nghttp2_frame_pack_rst_stream with error code 1000000009 (0x3B9ACA09)
        var wire_rst: u8[..32] = [];
        internal::emit_rst_stream(1000000007, 1000000009, wire_rst);
        sub.assert_eq(wire_rst.len, 13, "RST_STREAM frame is 9B header + 4B payload = 13B");

        let r_hdr, r_err = internal::parse_frame_header(wire_rst[..9]);
        sub.assert_eq(r_err, rfc::H2_ERR_NO_ERROR, "RST_STREAM header parsed");
        sub.assert_eq(r_hdr.frame_type, rfc::H2_FRAME_RST_STREAM, "frame type is RST_STREAM");
        sub.assert_eq(r_hdr.stream_id, 1000000007, "stream_id 1000000007 preserved");
        let code = core::read_be_u32(wire_rst[..], 9);
        sub.assert_eq(code, 1000000009, "unknown 32-bit error code 1000000009 preserved verbatim");

        // HEADERS frame with both FLAG_PADDED (0x08) and FLAG_PRIORITY (0x20)
        // Payload: PadLen=2 (1B) + [Exclusive=1 | StreamDep=3 (4B) + Weight=12 (1B)] + HPACK(3B: 0x82,0x87,0x84) + Padding(2B) = 11B
        let h_hdr = internal::FrameHeader {
            length:     11,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_PADDED | rfc::H2_FLAG_PRIORITY,
            stream_id:  1,
        };
        let h_payload: u8[11] = [
            0x02,                   // Pad length = 2
            0x80, 0x00, 0x00, 0x03, // Exclusive=1, Stream Dependency=3
            12,                     // Weight = 12
            0x82, 0x87, 0x84,       // :method GET, :scheme https, :path /
            0x00, 0x00,             // 2 bytes padding
        ];
        let unpadded, pad_err = internal::extract_padded_frame_payload(h_hdr, h_payload[..]);
        sub.assert_eq(pad_err, rfc::H2_ERR_NO_ERROR, "padded + priority HEADERS payload extracted");
        sub.assert_eq(unpadded.len, 8, "unpadded length is 5B priority + 3B hpack = 8B");
    };
}

// 32. Ported Session, Mandatory Headers, Content-Length & Flow Control Vectors (vendor/nghttp2/tests/nghttp2_session_test.c)
fn test_nghttp2_session_and_http_semantics(t: lit::T&) {
    t.run("NGHTTP2-SESS-01: Mandatory Pseudo-Headers & Forbidden Connection Headers (test_nghttp2_http_mandatory_headers)") { sub =>
        // 1. Forbidden connection-specific headers: connection, keep-alive, proxy-connection, transfer-encoding, upgrade
        let forbidden_names: const u8[:][5] = [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ];
        for fname in forbidden_names {
            var dt = internal::new_dynamic_table(4096);
            var hblock: u8[..128] = [0x82, 0x87, 0x84]; // :method GET, :scheme https, :path /
            hblock.push(0x00);
            hblock.push(fname.len as u8);
            hblock.append(fname);
            hblock.push(3);
            hblock.append("val");
            var pseudo = internal::H2PseudoHeaders { .. };
            var out = wing::HeaderMap { .. };
            let err = internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
            sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "forbidden connection-specific header rejected");
        }

        // 2. "te" header: only "trailers" is valid; "gzip" or "chunked" or "trailers, deflate" must fail
        let bad_te_vals: const u8[:][3] = ["gzip", "chunked", "trailers, deflate"];
        for bte in bad_te_vals {
            var dt = internal::new_dynamic_table(4096);
            var hblock: u8[..128] = [0x82, 0x87, 0x84];
            hblock.push(0x00);
            hblock.push(2);
            hblock.append("te");
            hblock.push(bte.len as u8);
            hblock.append(bte);
            var pseudo = internal::H2PseudoHeaders { .. };
            var out = wing::HeaderMap { .. };
            let err = internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
            sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "TE header != 'trailers' rejected");
        }
        var dt_te_ok = internal::new_dynamic_table(4096);
        var hb_te_ok: u8[..128] = [0x82, 0x87, 0x84];
        hb_te_ok.push(0x00);
        hb_te_ok.push(2);
        hb_te_ok.append("te");
        hb_te_ok.push(8);
        hb_te_ok.append("trailers");
        var pseudo_te = internal::H2PseudoHeaders { .. };
        var out_te = wing::HeaderMap { .. };
        sub.assert_eq(internal::decode_hpack_to_map(dt_te_ok, hb_te_ok[..], pseudo_te, out_te), rfc::H2_ERR_NO_ERROR, "TE: trailers accepted");

        // 3. Uppercase letters in header names (RFC 9113 §8.2.1) must fail
        let upper_names: const u8[:][4] = ["Content-Type", "X-Custom", "accept-Encoding", ":Method"];
        for uname in upper_names {
            var dt = internal::new_dynamic_table(4096);
            var hblock: u8[..128] = [0x82, 0x87, 0x84];
            hblock.push(0x00);
            hblock.push(uname.len as u8);
            hblock.append(uname);
            hblock.push(3);
            hblock.append("val");
            var pseudo = internal::H2PseudoHeaders { .. };
            var out = wing::HeaderMap { .. };
            let err = internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
            sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "uppercase character in header name rejected");
        }
    };

    t.run("NGHTTP2-SESS-02: Invalid Frame Header Rules Matrix (test_nghttp2_session_recv_invalid_frame)") { sub =>
        // 1. DATA on stream 0 -> PROTOCOL_ERROR
        let h_data0 = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_DATA, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_data0), rfc::H2_ERR_PROTOCOL_ERROR, "DATA on stream 0 rejected");

        // 2. HEADERS on stream 0 -> PROTOCOL_ERROR
        let h_hdr0 = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_HEADERS, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_hdr0), rfc::H2_ERR_PROTOCOL_ERROR, "HEADERS on stream 0 rejected");

        // 3. PRIORITY on stream 0 -> PROTOCOL_ERROR; PRIORITY with length != 5 -> FRAME_SIZE_ERROR
        let h_prio0 = internal::FrameHeader { length: 5, frame_type: rfc::H2_FRAME_PRIORITY, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_prio0), rfc::H2_ERR_PROTOCOL_ERROR, "PRIORITY on stream 0 rejected");
        let h_prio6 = internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_PRIORITY, flags: 0, stream_id: 1 };
        sub.assert_eq(internal::validate_frame_header_rules(h_prio6), rfc::H2_ERR_FRAME_SIZE_ERROR, "PRIORITY length 6 rejected");

        // 4. RST_STREAM on stream 0 -> PROTOCOL_ERROR; RST_STREAM length != 4 -> FRAME_SIZE_ERROR
        let h_rst0 = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_RST_STREAM, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_rst0), rfc::H2_ERR_PROTOCOL_ERROR, "RST_STREAM on stream 0 rejected");
        let h_rst3 = internal::FrameHeader { length: 3, frame_type: rfc::H2_FRAME_RST_STREAM, flags: 0, stream_id: 1 };
        sub.assert_eq(internal::validate_frame_header_rules(h_rst3), rfc::H2_ERR_FRAME_SIZE_ERROR, "RST_STREAM length 3 rejected");

        // 5. SETTINGS on stream != 0 -> PROTOCOL_ERROR; SETTINGS ACK with length > 0 -> FRAME_SIZE_ERROR; length % 6 != 0 -> FRAME_SIZE_ERROR
        let h_set1 = internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 1 };
        sub.assert_eq(internal::validate_frame_header_rules(h_set1), rfc::H2_ERR_PROTOCOL_ERROR, "SETTINGS on stream 1 rejected");
        let h_set_ack6 = internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: rfc::H2_FLAG_ACK, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_set_ack6), rfc::H2_ERR_FRAME_SIZE_ERROR, "SETTINGS ACK with payload length 6 rejected");
        let h_set5 = internal::FrameHeader { length: 5, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_set5), rfc::H2_ERR_FRAME_SIZE_ERROR, "SETTINGS length 5 (not multiple of 6) rejected");

        // 6. PING on stream != 0 -> PROTOCOL_ERROR; PING length != 8 -> FRAME_SIZE_ERROR
        let h_ping1 = internal::FrameHeader { length: 8, frame_type: rfc::H2_FRAME_PING, flags: 0, stream_id: 1 };
        sub.assert_eq(internal::validate_frame_header_rules(h_ping1), rfc::H2_ERR_PROTOCOL_ERROR, "PING on stream 1 rejected");
        let h_ping7 = internal::FrameHeader { length: 7, frame_type: rfc::H2_FRAME_PING, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_ping7), rfc::H2_ERR_FRAME_SIZE_ERROR, "PING length 7 rejected");

        // 7. GOAWAY on stream != 0 -> PROTOCOL_ERROR; GOAWAY length < 8 -> FRAME_SIZE_ERROR
        let h_ga1 = internal::FrameHeader { length: 8, frame_type: rfc::H2_FRAME_GOAWAY, flags: 0, stream_id: 1 };
        sub.assert_eq(internal::validate_frame_header_rules(h_ga1), rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY on stream 1 rejected");
        let h_ga7 = internal::FrameHeader { length: 7, frame_type: rfc::H2_FRAME_GOAWAY, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_ga7), rfc::H2_ERR_FRAME_SIZE_ERROR, "GOAWAY length 7 rejected");

        // 8. WINDOW_UPDATE length != 4 -> FRAME_SIZE_ERROR
        let h_wu5 = internal::FrameHeader { length: 5, frame_type: rfc::H2_FRAME_WINDOW_UPDATE, flags: 0, stream_id: 0 };
        sub.assert_eq(internal::validate_frame_header_rules(h_wu5), rfc::H2_ERR_FRAME_SIZE_ERROR, "WINDOW_UPDATE length 5 rejected");
    };

    t.run("NGHTTP2-SESS-03: Two-Level Flow Control & Initial Window Adjustment (test_nghttp2_session_flow_control)") { sub =>
        var sess = internal::new_session_state();
        // Open streams 1 and 3
        let hdr1 = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 1 };
        let hdr3 = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_HEADERS, stream_id: 3 };
        sub.assert_eq(internal::on_ingress_frame_header(sess, hdr1, 0), rfc::H2_ERR_NO_ERROR, "open stream 1");
        sub.assert_eq(internal::on_ingress_frame_header(sess, hdr3, 0), rfc::H2_ERR_NO_ERROR, "open stream 3");

        // Default initial window is 65535
        sub.assert_eq(sess.streams[0].send_window, 65535, "stream 1 initial send_window 65535");
        sess.streams[0].send_window -= 40000; // now 25535

        // Peer sends SETTINGS_INITIAL_WINDOW_SIZE = 10000 (delta = -55535)
        // Stream 1 send_window must become 25535 - 55535 = -30000 (negative window permitted per RFC 9113 §6.9.2!)
        let err_s = internal::apply_peer_initial_window_size_delta(sess, 10000);
        sub.assert_eq(err_s, rfc::H2_ERR_NO_ERROR, "apply SETTINGS_INITIAL_WINDOW_SIZE = 10000");
        sub.assert_eq(sess.streams[0].send_window, -30000, "stream 1 send_window adjusted to -30000");
        sub.assert_eq(sess.streams[1].send_window, 10000, "stream 3 send_window adjusted to 10000");
        sub.assert_eq(internal::compute_stream_send_quota(sess, 1), 0, "negative window yields 0 send quota");
        sub.assert_eq(internal::compute_stream_send_quota(sess, 3), 10000, "stream 3 send quota is 10000");

        // Peer sends SETTINGS_INITIAL_WINDOW_SIZE = 0x80000000 (> 2^31 - 1) -> FLOW_CONTROL_ERROR
        let err_bad = internal::apply_peer_initial_window_size_delta(sess, 0x80000000);
        sub.assert_eq(err_bad, rfc::H2_ERR_FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE > 2^31-1 rejected with FLOW_CONTROL_ERROR");
    };

    t.run("NGHTTP2-HTTP-02: Extended CONNECT Ordering, OPTIONS *, Authority/Host & Content-Length Mismatch (nghttp2_http_test.c)") { sub =>
        // 1. RFC 8441 Extended CONNECT with :protocol appearing AFTER :method, :scheme, :path, :authority
        var dt_ext = internal::new_dynamic_table(4096);
        var hb_ext: u8[..256] = [];
        internal::encode_hpack_field(dt_ext, hb_ext, ":method", "CONNECT", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_ext, hb_ext, ":scheme", "https", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_ext, hb_ext, ":path", "/chat", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_ext, hb_ext, ":authority", "example.com", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_ext, hb_ext, ":protocol", "websocket", internal::HpackIndexing.None, false);

        var dec_dt1 = internal::new_dynamic_table(4096);
        var pseudo_ext = internal::H2PseudoHeaders { .. };
        var out_ext = wing::HeaderMap { .. };
        let err_ext = internal::decode_hpack_to_map(dec_dt1, hb_ext[..], pseudo_ext, out_ext);
        sub.assert_eq(err_ext, rfc::H2_ERR_NO_ERROR, "Extended CONNECT with trailing :protocol accepted");
        sub.assert_eq(pseudo_ext.protocol[..], "websocket", ":protocol is websocket");

        // 2. Classic CONNECT with :scheme or :path (without :protocol) must fail with PROTOCOL_ERROR
        var dt_bad_conn = internal::new_dynamic_table(4096);
        var hb_bad_conn: u8[..256] = [];
        internal::encode_hpack_field(dt_bad_conn, hb_bad_conn, ":method", "CONNECT", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_bad_conn, hb_bad_conn, ":scheme", "https", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_bad_conn, hb_bad_conn, ":authority", "example.com:443", internal::HpackIndexing.None, false);
        var pseudo_bc = internal::H2PseudoHeaders { .. };
        var out_bc = wing::HeaderMap { .. };
        sub.assert_eq(
            internal::decode_hpack_to_map(dt_bad_conn, hb_bad_conn[..], pseudo_bc, out_bc),
            rfc::H2_ERR_PROTOCOL_ERROR,
            "classic CONNECT with :scheme and no :protocol rejected",
        );

        // 3. OPTIONS with :path = "*" accepted; GET with :path = "*" rejected (both orderings)
        var dt_opt = internal::new_dynamic_table(4096);
        var hb_opt: u8[..128] = [];
        internal::encode_hpack_field(dt_opt, hb_opt, ":method", "OPTIONS", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_opt, hb_opt, ":scheme", "https", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_opt, hb_opt, ":path", "*", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_opt, hb_opt, ":authority", "example.com", internal::HpackIndexing.None, false);
        var pseudo_opt = internal::H2PseudoHeaders { .. };
        var out_opt = wing::HeaderMap { .. };
        sub.assert_eq(internal::decode_hpack_to_map(dt_opt, hb_opt[..], pseudo_opt, out_opt), rfc::H2_ERR_NO_ERROR, "OPTIONS * accepted");

        var dt_get_star1 = internal::new_dynamic_table(4096);
        var hb_get_star1: u8[..128] = [];
        internal::encode_hpack_field(dt_get_star1, hb_get_star1, ":method", "GET", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_get_star1, hb_get_star1, ":scheme", "https", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_get_star1, hb_get_star1, ":path", "*", internal::HpackIndexing.None, false);
        var pseudo_gs1 = internal::H2PseudoHeaders { .. };
        var out_gs1 = wing::HeaderMap { .. };
        sub.assert_eq(internal::decode_hpack_to_map(dt_get_star1, hb_get_star1[..], pseudo_gs1, out_gs1), rfc::H2_ERR_PROTOCOL_ERROR, "GET * (:method before :path) rejected");

        var dt_get_star2 = internal::new_dynamic_table(4096);
        var hb_get_star2: u8[..128] = [];
        internal::encode_hpack_field(dt_get_star2, hb_get_star2, ":path", "*", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_get_star2, hb_get_star2, ":method", "GET", internal::HpackIndexing.None, false);
        internal::encode_hpack_field(dt_get_star2, hb_get_star2, ":scheme", "https", internal::HpackIndexing.None, false);
        var pseudo_gs2 = internal::H2PseudoHeaders { .. };
        var out_gs2 = wing::HeaderMap { .. };
        sub.assert_eq(internal::decode_hpack_to_map(dt_get_star2, hb_get_star2[..], pseudo_gs2, out_gs2), rfc::H2_ERR_PROTOCOL_ERROR, "GET * (:path before :method) rejected");

        // 4. Content-Length mismatch with DATA payload length triggers RST_STREAM(PROTOCOL_ERROR) (RFC 9113 §8.1.1)
        var sess_cl = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline_cl = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer_cl = internal::new_connection_timer(30000000000, 1000000000);
        var wire_cl: u8[..512] = [];
        wire_cl.append(rfc::H2_CLIENT_PREFACE[..]);

        var client_dt = internal::new_dynamic_table(4096);
        var cl_hblock: u8[..128] = [];
        internal::encode_hpack_field(client_dt, cl_hblock, ":method", "POST", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_dt, cl_hblock, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_dt, cl_hblock, ":path", "/upload", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_dt, cl_hblock, ":authority", "localhost", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_dt, cl_hblock, "content-length", "10", internal::HpackIndexing.None, false);

        let h_hdr_cl = internal::FrameHeader {
            length:     cl_hblock.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        internal::encode_frame_header_to(h_hdr_cl, wire_cl);
        wire_cl.append(cl_hblock[..]);
        // Send only 4 bytes with END_STREAM when content-length promised 10 bytes
        encode_client_data(1, "abcd", true, wire_cl);

        var out_cl: u8[..512] = [];
        let _, ok_cl_ing = internal::handle_h2_server_ingress(sess_cl, pipeline_cl, timer_cl, "127.0.0.1", wire_cl[..], 1000, out_cl);
        sub.assert_true(ok_cl_ing, "connection stays alive on stream content-length mismatch");
        sub.assert_gt(out_cl.len, 33, "RST_STREAM emitted after server settings");
        let rst_f, _ = internal::parse_frame_header(out_cl[33..42]);
        sub.assert_eq(rst_f.frame_type, rfc::H2_FRAME_RST_STREAM, "emitted RST_STREAM for content-length mismatch");
        sub.assert_eq(core::read_be_u32(out_cl[..], 42), rfc::H2_ERR_PROTOCOL_ERROR, "RST_STREAM code is PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// F015: H2 ExpectContinuation, Compression Dict, Forwarded, HSTS IPv6 & Trace
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 33. F015 H2 Continuation, Dict, Forwarded & Tracestate
// ----------------------------------------------------------------------------
fn test_f015_h2_dict_forwarded_hsts_trace(t: lit::T&) {
    t.run("H2 on_ingress_frame_header returns ProtocolError on bad frame during continuation") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr_open = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0, // END_HEADERS not set -> ExpectContinuation
            stream_id:  1,
        };
        let err1 = internal::on_ingress_frame_header(conn, hdr_open, 0);
        sub.assert_true(err1 == rfc::H2_ERR_NO_ERROR, "HEADERS opens continuation state");

        // Send a PING with invalid length 4 while ExpectContinuation is active
        let bad_ping = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        let err2 = internal::on_ingress_frame_header(conn, bad_ping, 0);
        sub.assert_true(err2 == rfc::H2_ERR_PROTOCOL_ERROR, "Non-CONTINUATION frame during ExpectContinuation MUST return ProtocolError per RFC 9113 §6.10");
    };

    t.run("parse_use_as_dictionary_header rejects oversized id even when followed by valid match") { sub =>
        var raw: u8[..256] = [];
        raw.append("id=\"");
        for i in 80 { raw.push('x'); }
        raw.append("\", match=\"/assets/*\"");

        let p, ok = wing::parse_use_as_dictionary_header(raw[..]);
        sub.assert_false(ok, "Oversized id followed by valid match MUST fail parsing");
    };

    t.run("parse_forwarded_element rejects oversized parameter value") { sub =>
        var raw: u8[..300] = [];
        raw.append("for=\"");
        for i in 200 { raw.push('1'); }
        raw.append("\";proto=https");

        var elem = wing::ForwardedElement { .. };
        let ok = wing::parse_forwarded_element(raw[..], elem);
        sub.assert_false(ok, "Forwarded element with oversized for parameter MUST fail instead of ignoring error");
    };

    t.run("parse_tracestate rejects duplicate keys per W3C Section 3.3.1") { sub =>
        let ts, ok = wing::parse_tracestate("rojo=1,rojo=2");
        sub.assert_false(ok, "Duplicate key in tracestate MUST be rejected per W3C §3.3.1");
    };
}

// ----------------------------------------------------------------------------
// 34. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters
// ----------------------------------------------------------------------------
fn test_h2_field_value_ctl_rejection(t: lit::T&) {
    t.run("Valid field value without control characters is accepted") { sub =>
        let ok = internal::validate_h2_field_syntax("custom-header", "valid-value-123");
        sub.assert_true(ok, "Standard printable ASCII value must be valid");
    };

    t.run("Field value with HTAB (0x09) inside is accepted per RFC 9113 §8.2.1") { sub =>
        let ok = internal::validate_h2_field_syntax("custom-header", "val\twith\ttabs");
        sub.assert_true(ok, "HTAB inside field value is permitted");
    };

    t.run("Field value with VT (0x0B) MUST be rejected") { sub =>
        // RFC 9113 Section 8.2.1: CTL characters 0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F MUST trigger protocol error
        let ok = internal::validate_h2_field_syntax("custom-header", "val\x0bwith-vt");
        sub.assert_false(ok, "VT (0x0B) in field value MUST be rejected");
    };

    t.run("Field value with FF (0x0C) MUST be rejected") { sub =>
        let ok = internal::validate_h2_field_syntax("custom-header", "val\x0cwith-ff");
        sub.assert_false(ok, "FF (0x0C) in field value MUST be rejected");
    };

    t.run("Field value with ESC (0x1B) MUST be rejected") { sub =>
        let ok = internal::validate_h2_field_syntax("custom-header", "val\x1bwith-esc");
        sub.assert_false(ok, "ESC (0x1B) in field value MUST be rejected");
    };

    t.run("Field value with DEL (0x7F) MUST be rejected") { sub =>
        let ok = internal::validate_h2_field_syntax("custom-header", "val\x7fwith-del");
        sub.assert_false(ok, "DEL (0x7F) in field value MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 35. RFC 9113 §8.3: Undefined Pseudo-Headers MUST Return PROTOCOL_ERROR
// ----------------------------------------------------------------------------
fn test_h2_undefined_pseudo_header_rejection(t: lit::T&) {
    t.run("Valid standard pseudo-headers accepted in order") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var list = wing::HeaderMap { .. };
        let err1 = internal::validate_header_ordering_and_rules(pseudo, list, ":method", "GET");
        sub.assert_eq(err1, rfc::H2_ERR_NO_ERROR, ":method is valid pseudo-header");

        let err2 = internal::validate_header_ordering_and_rules(pseudo, list, ":path", "/index.html");
        sub.assert_eq(err2, rfc::H2_ERR_NO_ERROR, ":path is valid pseudo-header");
    };

    t.run("Undefined pseudo-header :custom MUST return ERR_PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 8.3: "Endpoints MUST treat a request or response that contains an undefined
        // or invalid pseudo-header field as malformed (Section 8.1.1)."
        var pseudo = internal::H2PseudoHeaders { .. };
        var list = wing::HeaderMap { .. };
        let err = internal::validate_header_ordering_and_rules(pseudo, list, ":custom", "val");
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "Undefined pseudo-header :custom MUST return ERR_PROTOCOL_ERROR");
    };

    t.run("Undefined pseudo-header :fake MUST return ERR_PROTOCOL_ERROR") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var list = wing::HeaderMap { .. };
        let err = internal::validate_header_ordering_and_rules(pseudo, list, ":fake", "exploit");
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "Undefined pseudo-header :fake MUST return ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 36. RFC 9113 §6.6: Frame Header Rules for PUSH_PROMISE
// ----------------------------------------------------------------------------
fn test_h2_push_promise_frame_rules(t: lit::T&) {
    t.run("PUSH_PROMISE on stream 0 MUST return ERR_PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 6.6: "PUSH_PROMISE frames MUST be associated with an existing, peer-initiated stream.
        // If the stream identifier field specifies the value 0x00, a recipient MUST respond with a connection error of type PROTOCOL_ERROR."
        let hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      0,
            stream_id:  0,
        };
        let err = internal::validate_frame_header_rules(hdr);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "PUSH_PROMISE on stream 0 MUST return PROTOCOL_ERROR");
    };

    t.run("PUSH_PROMISE with length < 4 MUST return ERR_FRAME_SIZE_ERROR") { sub =>
        // RFC 9113 Section 6.6: Promised Stream ID is 4 bytes. Unpadded PUSH_PROMISE < 4 bytes is invalid.
        let hdr = internal::FrameHeader {
            length:     3,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      0,
            stream_id:  1,
        };
        let err = internal::validate_frame_header_rules(hdr);
        sub.assert_eq(err, rfc::H2_ERR_FRAME_SIZE_ERROR, "Unpadded PUSH_PROMISE < 4 bytes MUST return FRAME_SIZE_ERROR");
    };

    t.run("Padded PUSH_PROMISE with length < 5 MUST return ERR_FRAME_SIZE_ERROR") { sub =>
        // With PADDED flag, Pad Length (1 byte) + Promised Stream ID (4 bytes) = 5 bytes minimum
        let hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      rfc::H2_FLAG_PADDED,
            stream_id:  1,
        };
        let err = internal::validate_frame_header_rules(hdr);
        sub.assert_eq(err, rfc::H2_ERR_FRAME_SIZE_ERROR, "Padded PUSH_PROMISE < 5 bytes MUST return FRAME_SIZE_ERROR");
    };
}

// --- Component: regress_issues_batch07 ---
// Phase 7 RED test suite based on security issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and edge cases that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Frame Stream ID Invariant (Stream ID MUST Be 0)
// 2. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Without Leading Slash Must Not Override Default Path
// 3. RFC 9110 §13.2.1: Cache-Control max-age Arithmetic Overflow Clamping (Saturates to MAX_DELTA_SECONDS)
// 4. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present
// 5. RFC 6455 §5.5 & Go #7825: WebSocket Control Frame Standalone Empty Ping / Pong Roundtrip
// 6. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages
// 7. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense
// 8. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = '*' ONLY for OPTIONS Method
// 9. RFC 9113 §8.3: HTTP/2 Request and Response Pseudo-Header Segregation (:status vs :method)
// 10. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicate Host Header Rejection
// 11. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys (H2c vs Https)
// 12. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection (H3_ERR_STREAM_CREATION)
// 13. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon

// ----------------------------------------------------------------------------
// 37. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Frame Stream ID Invariant
// ----------------------------------------------------------------------------
fn test_h2_goaway_stream_id_zero(t: lit::T&) {
    t.run("GOAWAY frame on stream_id > 0 must return ERR_PROTOCOL_ERROR (RFC 9113 §6.8)") { sub =>
        // RFC 9113 Section 6.8:
        // "GOAWAY frames apply to the connection, not a specific stream, so the stream identifier
        // for a GOAWAY frame MUST be zero (0x00)."
        // "An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00
        // as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
        let bad_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_GOAWAY,
            flags:      0,
            stream_id:  1, // Invalid: GOAWAY MUST be on stream 0
        };
        let err = internal::validate_frame_header_rules(bad_hdr);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY on stream 1 MUST be rejected with PROTOCOL_ERROR (RFC 9113 §6.8)");

        let bad_hdr3 = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_GOAWAY,
            flags:      0,
            stream_id:  3,
        };
        let err3 = internal::validate_frame_header_rules(bad_hdr3);
        sub.assert_eq(err3, rfc::H2_ERR_PROTOCOL_ERROR, "GOAWAY on stream 3 MUST be rejected with PROTOCOL_ERROR (RFC 9113 §6.8)");

        let good_hdr = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_GOAWAY,
            flags:      0,
            stream_id:  0,
        };
        let ok_err = internal::validate_frame_header_rules(good_hdr);
        sub.assert_eq(ok_err, rfc::H2_ERR_NO_ERROR, "GOAWAY on stream 0 is valid");
    };
}

// ----------------------------------------------------------------------------
// 38. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present
// ----------------------------------------------------------------------------
fn test_h2_connect_scheme_path_rejection(t: lit::T&) {
    t.run("Standard CONNECT with :path present MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "CONNECT");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method CONNECT accepted");

        let ok_auth = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "proxy.example.com:443");
        sub.assert_eq(ok_auth, rfc::H2_ERR_NO_ERROR, ":authority accepted");

        // Standard CONNECT with :path must be rejected as PROTOCOL_ERROR!
        let err_path = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "/");
        sub.assert_eq(err_path, rfc::H2_ERR_PROTOCOL_ERROR, "Standard CONNECT with :path MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)");
    };

    t.run("Standard CONNECT with :scheme present MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "CONNECT");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method CONNECT accepted");

        let ok_auth = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "proxy.example.com:443");
        sub.assert_eq(ok_auth, rfc::H2_ERR_NO_ERROR, ":authority accepted");

        // Standard CONNECT with :scheme must be rejected as PROTOCOL_ERROR!
        let err_scheme = internal::validate_header_ordering_and_rules(pseudo, headers, ":scheme", "https");
        sub.assert_eq(err_scheme, rfc::H2_ERR_PROTOCOL_ERROR, "Standard CONNECT with :scheme MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)");
    };
}

// ----------------------------------------------------------------------------
// 39. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = "*" ONLY for OPTIONS
// ----------------------------------------------------------------------------
fn test_h2_asterisk_path_only_for_options(t: lit::T&) {
    t.run("Asterisk-form :path '*' is valid for OPTIONS method") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "OPTIONS");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method OPTIONS accepted");

        let ok_path = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "*");
        sub.assert_eq(ok_path, rfc::H2_ERR_NO_ERROR, ":path '*' accepted for OPTIONS");
    };

    t.run("Asterisk-form :path '*' on GET method MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method GET accepted");

        let err_path = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "*");
        sub.assert_eq(err_path, rfc::H2_ERR_PROTOCOL_ERROR, "GET with :path '*' MUST be rejected with PROTOCOL_ERROR (RFC 9113 §8.3.1)");
    };
}

// ----------------------------------------------------------------------------
// 40. RFC 9113 §8.3: Request and Response Pseudo-Header Segregation
// ----------------------------------------------------------------------------
fn test_h2_pseudo_header_request_response_segregation(t: lit::T&) {
    t.run("Response pseudo-header :status in Request header block MUST return ERR_PROTOCOL_ERROR") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method GET accepted");

        let err_status = internal::validate_header_ordering_and_rules(pseudo, headers, ":status", "200");
        sub.assert_eq(err_status, rfc::H2_ERR_PROTOCOL_ERROR, ":status in request header block MUST return PROTOCOL_ERROR (RFC 9113 §8.3)");
    };

    t.run("Request pseudo-header :method in Response header block MUST return ERR_PROTOCOL_ERROR") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_status = internal::validate_header_ordering_and_rules(pseudo, headers, ":status", "200");
        sub.assert_eq(ok_status, rfc::H2_ERR_NO_ERROR, ":status 200 accepted");

        let err_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");
        sub.assert_eq(err_meth, rfc::H2_ERR_PROTOCOL_ERROR, ":method in response header block MUST return PROTOCOL_ERROR (RFC 9113 §8.3)");
    };
}

// ----------------------------------------------------------------------------
// 41. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicates
// ----------------------------------------------------------------------------
fn test_h2_authority_host_consistency_and_duplicates(t: lit::T&) {
    t.run("Matching :authority and Host headers are accepted") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_auth = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com");
        sub.assert_eq(ok_auth, rfc::H2_ERR_NO_ERROR, ":authority accepted");

        let ok_host = internal::validate_header_ordering_and_rules(pseudo, headers, "host", "example.com");
        sub.assert_eq(ok_host, rfc::H2_ERR_NO_ERROR, "Matching Host header accepted");
    };

    t.run("Conflicting :authority and Host headers MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_auth = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com");
        sub.assert_eq(ok_auth, rfc::H2_ERR_NO_ERROR, ":authority accepted");

        let err_host = internal::validate_header_ordering_and_rules(pseudo, headers, "host", "attacker.com");
        sub.assert_eq(err_host, rfc::H2_ERR_PROTOCOL_ERROR, "Conflicting Host 'attacker.com' MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)");
    };

    t.run("Multiple Host headers in HTTP/2 MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.2.1)") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_host1 = internal::validate_header_ordering_and_rules(pseudo, headers, "host", "example.com");
        sub.assert_eq(ok_host1, rfc::H2_ERR_NO_ERROR, "First Host accepted");

        let err_host2 = internal::validate_header_ordering_and_rules(pseudo, headers, "host", "example.com");
        sub.assert_eq(err_host2, rfc::H2_ERR_PROTOCOL_ERROR, "Duplicate Host header MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.2.1)");
    };
}

// --- Component: regress_issues_batch08 ---
// Phase 8 RED test suite based on security issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and edge cases:
//
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant
// 2. RFC 9113 §6.8 & Go #82365: HTTP/2 Inbound Stream Rejection After GOAWAY
// 3. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header RFC 3986 Character Validation
// 4. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers
// 5. RFC 6455 §4.2.1: WebSocket Upgrade Handshake Missing Host Header Rejection
// 6. RFC 6455 §4.2.2: WebSocket Subprotocol Agreement Verification
// 7. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection

// ----------------------------------------------------------------------------
// 42. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant
// ----------------------------------------------------------------------------
fn test_h2_goaway_last_stream_id_peer_role(t: lit::T&) {
    t.run("Client GOAWAY with odd stream ID sent to Server MUST be rejected with PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 6.8 & Go #80759:
        // "Since streams initiated by a client have odd stream identifiers and streams initiated
        // by a server have even stream identifiers, the Last-Stream-ID sent by a client MUST be
        // an even stream identifier or zero (streams initiated by the peer)."
        // Client sent stream 1 or 3 -> invalid!
        let valid_client_0 = rfc::validate_goaway_last_stream_id(0, true);
        sub.assert_true(valid_client_0, "Client GOAWAY with last_stream_id=0 is valid");

        let valid_client_even = rfc::validate_goaway_last_stream_id(2, true);
        sub.assert_true(valid_client_even, "Client GOAWAY with last_stream_id=2 (server stream) is valid");

        let invalid_client_odd1 = rfc::validate_goaway_last_stream_id(1, true);
        sub.assert_false(invalid_client_odd1, "Client GOAWAY with last_stream_id=1 MUST be rejected (Go #80759)");

        let invalid_client_odd3 = rfc::validate_goaway_last_stream_id(3, true);
        sub.assert_false(invalid_client_odd3, "Client GOAWAY with last_stream_id=3 MUST be rejected (Go #80759)");
    };

    t.run("Server GOAWAY with even stream ID > 0 sent to Client MUST be rejected with PROTOCOL_ERROR") { sub =>
        // Server sent stream 2 or 4 -> invalid! Server can only acknowledge client streams (odd) or 0.
        let valid_server_0 = rfc::validate_goaway_last_stream_id(0, false);
        sub.assert_true(valid_server_0, "Server GOAWAY with last_stream_id=0 is valid");

        let valid_server_odd = rfc::validate_goaway_last_stream_id(1, false);
        sub.assert_true(valid_server_odd, "Server GOAWAY with last_stream_id=1 (client stream) is valid");

        let valid_server_max = rfc::validate_goaway_last_stream_id(0x7FFFFFFF, false);
        sub.assert_true(valid_server_max, "Server GOAWAY with 2^31-1 (graceful shutdown) is valid");

        let invalid_server_even2 = rfc::validate_goaway_last_stream_id(2, false);
        sub.assert_false(invalid_server_even2, "Server GOAWAY with even stream 2 MUST be rejected (RFC 9113 §6.8)");

        let invalid_server_even4 = rfc::validate_goaway_last_stream_id(4, false);
        sub.assert_false(invalid_server_even4, "Server GOAWAY with even stream 4 MUST be rejected (RFC 9113 §6.8)");
    };
}

// ----------------------------------------------------------------------------
// 43. RFC 9113 §6.8 & Go #82365: HTTP/2 Stream Ingestion Blocked After GOAWAY
// ----------------------------------------------------------------------------
fn test_h2_stream_blocked_after_goaway(t: lit::T&) {
    t.run("New stream headers frame on stream > last_stream_id after GOAWAY MUST return ERR_REFUSED_STREAM") { sub =>
        // RFC 9113 Section 6.8 & Go #82365:
        // After receiving a GOAWAY frame with Last-Stream-ID = N, any new stream with ID > N
        // must be rejected.
        var conn = internal::new_h2_connection(0, 8192, false);
        let ok_ga = internal::apply_goaway(conn, 3, rfc::H2_ERR_NO_ERROR);
        sub.assert_eq(ok_ga, rfc::H2_ERR_NO_ERROR, "apply_goaway accepted");
        sub.assert_true(conn.goaway_received, "goaway_received flag is set");
        sub.assert_eq(conn.goaway_last_stream_id, 3, "goaway_last_stream_id is 3");

        // Attempting to open stream 5 (> 3) after GOAWAY must be refused
        let hdr_st5 = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  5,
        };
        let res_st5 = internal::handle_h2_headers_frame_header(conn, hdr_st5, 0);
        sub.assert_eq(res_st5, rfc::H2_ERR_REFUSED_STREAM, "Stream 5 > last_stream_id 3 MUST return REFUSED_STREAM");

        // Stream 1 (<= 3) was processed before GOAWAY, so it is not rejected as refused
        let hdr_st1 = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let res_st1 = internal::handle_h2_headers_frame_header(conn, hdr_st1, 0);
        sub.assert_eq(res_st1, rfc::H2_ERR_NO_ERROR, "Stream 1 <= last_stream_id 3 is accepted");
    };
}

// ----------------------------------------------------------------------------
// 44. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header Character Validation
// ----------------------------------------------------------------------------
fn test_h2_path_character_validation(t: lit::T&) {
    t.run("Path containing unescaped angle brackets (<>) MUST return ERR_PROTOCOL_ERROR (Go #77843)") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method GET accepted");

        // Unescaped '>' is forbidden in RFC 3986 pchar and query
        let err_gt = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "/api/search?q=test>123");
        sub.assert_eq(err_gt, rfc::H2_ERR_PROTOCOL_ERROR, "Path with raw '>' MUST return ERR_PROTOCOL_ERROR (Go #77843)");

        // Unescaped '<' is forbidden
        let err_lt = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "/api/search<test");
        sub.assert_eq(err_lt, rfc::H2_ERR_PROTOCOL_ERROR, "Path with raw '<' MUST return ERR_PROTOCOL_ERROR (Go #77843)");

        // Space inside path is forbidden
        let err_sp = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "/api/my test");
        sub.assert_eq(err_sp, rfc::H2_ERR_PROTOCOL_ERROR, "Path with interior space MUST return ERR_PROTOCOL_ERROR");

        // Properly percent-encoded path is valid
        let ok_encoded = internal::validate_header_ordering_and_rules(pseudo, headers, ":path", "/api/search?q=test%3E123");
        sub.assert_eq(ok_encoded, rfc::H2_ERR_NO_ERROR, "Percent-encoded path '/api/search?q=test%3E123' is valid");
    };
}

// ----------------------------------------------------------------------------
// 45. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers
// ----------------------------------------------------------------------------
fn test_h2_trailer_forbidden_pseudo_headers(t: lit::T&) {
    t.run("Pseudo-headers in HTTP/2 trailer block MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3)") { sub =>
        // RFC 9113 Section 8.3:
        // "Pseudo-header fields MUST NOT appear in trailer sections."
        var pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
        var trailers = wing::HeaderMap { .. };

        let err_status = internal::validate_header_ordering_and_rules(pseudo, trailers, ":status", "200");
        sub.assert_eq(err_status, rfc::H2_ERR_PROTOCOL_ERROR, "Pseudo-header :status in trailers MUST return PROTOCOL_ERROR");

        let err_path = internal::validate_header_ordering_and_rules(pseudo, trailers, ":path", "/index");
        sub.assert_eq(err_path, rfc::H2_ERR_PROTOCOL_ERROR, "Pseudo-header :path in trailers MUST return PROTOCOL_ERROR");

        // Regular trailer field is valid
        let ok_trailer = internal::validate_header_ordering_and_rules(pseudo, trailers, "grpc-status", "0");
        sub.assert_eq(ok_trailer, rfc::H2_ERR_NO_ERROR, "Regular trailer field 'grpc-status' is valid");
    };
}

// ----------------------------------------------------------------------------
// 46. RFC 9113 §8.3.1 & uWebSockets #1949: HTTP/2 :authority Forbidden Characters
// ----------------------------------------------------------------------------
fn test_h2_authority_character_validation(t: lit::T&) {
    t.run(":authority with path, query, fragment or userinfo MUST return ERR_PROTOCOL_ERROR") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");
        sub.assert_eq(ok_meth, rfc::H2_ERR_NO_ERROR, ":method GET accepted");

        let err_path = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com/api");
        sub.assert_eq(err_path, rfc::H2_ERR_PROTOCOL_ERROR, ":authority with '/' MUST return ERR_PROTOCOL_ERROR");

        let err_query = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com?foo=1");
        sub.assert_eq(err_query, rfc::H2_ERR_PROTOCOL_ERROR, ":authority with '?' MUST return ERR_PROTOCOL_ERROR");

        let err_hash = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com#sec");
        sub.assert_eq(err_hash, rfc::H2_ERR_PROTOCOL_ERROR, ":authority with '#' MUST return ERR_PROTOCOL_ERROR");

        let err_user = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "admin@example.com");
        sub.assert_eq(err_user, rfc::H2_ERR_PROTOCOL_ERROR, ":authority with '@' MUST return ERR_PROTOCOL_ERROR");

        let ok_auth = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com:443");
        sub.assert_eq(ok_auth, rfc::H2_ERR_NO_ERROR, ":authority 'example.com:443' is valid");
    };
}

// ----------------------------------------------------------------------------
// 47. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields
// ----------------------------------------------------------------------------
fn test_h2_trailer_disallowed_fields(t: lit::T&) {
    t.run("Disallowed headers in HTTP/2 trailers MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.1.2)") { sub =>
        var pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
        var trailers = wing::HeaderMap { .. };

        let err_cl = internal::validate_header_ordering_and_rules(pseudo, trailers, "content-length", "100");
        sub.assert_eq(err_cl, rfc::H2_ERR_PROTOCOL_ERROR, "content-length in trailers MUST return PROTOCOL_ERROR");

        let err_te = internal::validate_header_ordering_and_rules(pseudo, trailers, "transfer-encoding", "chunked");
        sub.assert_eq(err_te, rfc::H2_ERR_PROTOCOL_ERROR, "transfer-encoding in trailers MUST return PROTOCOL_ERROR");

        let err_host = internal::validate_header_ordering_and_rules(pseudo, trailers, "host", "evil.com");
        sub.assert_eq(err_host, rfc::H2_ERR_PROTOCOL_ERROR, "host in trailers MUST return PROTOCOL_ERROR");

        let err_conn = internal::validate_header_ordering_and_rules(pseudo, trailers, "connection", "close");
        sub.assert_eq(err_conn, rfc::H2_ERR_PROTOCOL_ERROR, "connection in trailers MUST return PROTOCOL_ERROR");

        let err_tr = internal::validate_header_ordering_and_rules(pseudo, trailers, "trailer", "x-foo");
        sub.assert_eq(err_tr, rfc::H2_ERR_PROTOCOL_ERROR, "trailer in trailers MUST return PROTOCOL_ERROR");

        let ok_custom = internal::validate_header_ordering_and_rules(pseudo, trailers, "x-checksum-sha256", "abc123def");
        sub.assert_eq(ok_custom, rfc::H2_ERR_NO_ERROR, "Allowed trailer header 'x-checksum-sha256' is valid");
    };
}

// ----------------------------------------------------------------------------
// 48. RFC 9113 §6.5.2: HTTP/2 Client Rejection of SETTINGS_ENABLE_PUSH != 0
// ----------------------------------------------------------------------------
fn test_h2_client_settings_enable_push_rejection(t: lit::T&) {
    t.run("Client receiving SETTINGS_ENABLE_PUSH != 0 MUST return PROTOCOL_ERROR (RFC 9113 §6.5.2)") { sub =>
        // Server receiving ENABLE_PUSH = 1 from client is VALID
        let ok_server = internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_PUSH, 1, false);
        sub.assert_eq(ok_server, rfc::H2_ERR_NO_ERROR, "Server receiving ENABLE_PUSH=1 from client is valid");

        // Client receiving ENABLE_PUSH = 1 from server MUST be rejected
        let err_client = internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_PUSH, 1, true);
        sub.assert_eq(err_client, rfc::H2_ERR_PROTOCOL_ERROR, "Client receiving ENABLE_PUSH=1 from server MUST return ERR_PROTOCOL_ERROR");

        // Client receiving ENABLE_PUSH = 0 from server is VALID
        let ok_client0 = internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_PUSH, 0, true);
        sub.assert_eq(ok_client0, rfc::H2_ERR_NO_ERROR, "Client receiving ENABLE_PUSH=0 from server is valid");
    };
}

// ----------------------------------------------------------------------------
// 49. HPACK literal header with indexed name value > 16B abort (http2/hpack.goose)
// ----------------------------------------------------------------------------
fn test_hpack_literal_indexed_name_dynamic_value_overflow(t: lit::T&) {
    t.run("Literal header with indexed name pointing to dynamic table value > 16B MUST NOT abort") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Insert entry into dynamic table with name 'custom-header' and value '01234567890123456789' (20 bytes > 16)
        internal::insert_header(dt, "custom-header", "01234567890123456789");

        // Encode a Literal Header Field with Incremental Indexing - Indexed Name
        // Dynamic table index 62 is the newly added entry (static table has 61 entries)
        var wire: u8[..64] = [];
        // Bit pattern: 01xxxxxx (0x40 | index 62) -> 0x40 | 62 = 0x7E
        wire.push(0x7E);
        // New value as 7-bit string literal: 'newval' (len 6)
        wire.push(0x06);
        wire.append("newval");

        var out_pseudo = internal::H2PseudoHeaders { .. };
        var out_headers = wing::HeaderMap { .. };
        let err_code = internal::decode_hpack_to_map(dt, wire[..], out_pseudo, out_headers, 8192, false);
        sub.assert_eq(err_code, rfc::H2_ERR_NO_ERROR, "Literal header with indexed name from dynamic table MUST decode without bounds abort");
        sub.assert_eq(out_headers.entries.len, 1, "Decoded 1 header");
        sub.assert_eq(wing::entry_name(out_headers, out_headers.entries[0]), "custom-header", "Header name matches dynamic table entry");
        sub.assert_eq(wing::entry_value(out_headers, out_headers.entries[0]), "newval", "Header value matches literal value");
    };
}

// ----------------------------------------------------------------------------
// 50. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)
// ----------------------------------------------------------------------------
fn test_h2_authority_whitespace_rejection(t: lit::T&) {
    t.run(":authority with interior space MUST return ERR_PROTOCOL_ERROR") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let _ = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");

        let code = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com :80");
        sub.assert_eq(code, rfc::H2_ERR_PROTOCOL_ERROR, ":authority with space MUST be rejected with ERR_PROTOCOL_ERROR");
    };

    t.run(":authority with comma MUST return ERR_PROTOCOL_ERROR") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let _ = internal::validate_header_ordering_and_rules(pseudo, headers, ":method", "GET");

        let code = internal::validate_header_ordering_and_rules(pseudo, headers, ":authority", "example.com,evil.com");
        sub.assert_eq(code, rfc::H2_ERR_PROTOCOL_ERROR, ":authority with comma MUST be rejected with ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 51. HTTP/2 Server Multiplexer & HPACK (server/*, http2/*, http/*)
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_and_hpack_rfc9113(t: lit::T&) {
    t.run("H2 server ingress rejects invalid SETTINGS_MAX_FRAME_SIZE < 16384") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Client preface + SETTINGS frame with MAX_FRAME_SIZE = 0
        var wire_in: u8[..64] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // Frame header: len=6, type=4 (SETTINGS), flags=0, stream_id=0
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x06);
        wire_in.push(0x04);
        wire_in.push(0x00);
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00);
        // Setting ID 0x05 (MAX_FRAME_SIZE), val 0x00000000
        wire_in.push(0x00); wire_in.push(0x05);
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00);

        var out_wire: u8[..512] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Invalid SETTINGS_MAX_FRAME_SIZE MUST return ok == false and emit GOAWAY");
    };

    t.run("validate_stream_id_association rejects Priority and PushPromise on stream 0") { sub =>
        sub.assert_eq(rfc::validate_stream_id_association(0, rfc::H2_FRAME_PRIORITY), rfc::H2_ERR_PROTOCOL_ERROR, "Priority on stream 0 is ProtocolError");
        sub.assert_eq(rfc::validate_stream_id_association(0, rfc::H2_FRAME_PUSH_PROMISE), rfc::H2_ERR_PROTOCOL_ERROR, "PushPromise on stream 0 is ProtocolError");
        sub.assert_eq(rfc::validate_stream_id_association(1, rfc::H2_FRAME_GOAWAY), rfc::H2_ERR_PROTOCOL_ERROR, "GoAway on stream 1 is ProtocolError");
    };

    t.run("H2Connection enforces settings flood and single headers frame bounds") { sub =>
        var conn = internal::new_h2_connection(0);

        // 1. Single HEADERS frame exceeding max_header_list_size (8192) must trigger EnhanceYourCalm
        let big_hdr = internal::FrameHeader {
            length:     12000,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let err_big = internal::on_ingress_frame_header(conn, big_hdr, 0);
        sub.assert_eq(err_big, rfc::H2_ERR_ENHANCE_YOUR_CALM, "Single HEADERS > 8KB triggers EnhanceYourCalm");

        // 2. SETTINGS flood defense (CVE-2019-9515)
        var conn_set = internal::new_h2_connection(0);
        for _ in 64 {
            let sf = internal::FrameHeader {
                length:     6,
                frame_type: rfc::H2_FRAME_SETTINGS,
                flags:      0x0,
                stream_id:  0,
            };
            sub.assert_eq(internal::on_ingress_frame_header(conn_set, sf, 0), rfc::H2_ERR_NO_ERROR);
        }
        let sf_65 = internal::FrameHeader {
            length:     6,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0x0,
            stream_id:  0,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn_set, sf_65, 0), rfc::H2_ERR_ENHANCE_YOUR_CALM, "65th SETTINGS triggers EnhanceYourCalm");
    };
}

// --- Component: regress_issues_batch13 ---
// Phase 13 RED test suite: RFC Protocol Invariants, Payload Truncation Smuggling,
// Boundary Validations, and Safe Resource Limits.
//
// 1. HTTP/2 Content-Length desync, padding bounds & mandatory pseudo-headers (server/h2_multiplexer.goose)
// 2. WebSocket Connection header token parsing & unfragmented frame capacity (realtime/websocket.goose)
// 3. Client Redirect cross-origin Origin leak on 307/308 & fragment capacity (client/redirect.goose)
// 4. Server-Sent Events empty data dispatch & retry integer overflow (realtime/sse.goose)
// 5. Multipart boundary trailing space & parameter truncation smuggling (http/multipart.goose)
// 6. Connection pool TLD wildcard SAN defense & CONNECT response parser desync (net/pool.goose, net/proxy.goose)

// ----------------------------------------------------------------------------
// 52. HTTP/2 Server Multiplexer (server/h2_multiplexer.goose, http2/*)
// ----------------------------------------------------------------------------
fn has_rst_stream_for(wire: const u8[:], stream_id: u32) -> bool {
    var p: i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) | ((wire[p + 6] as u32) << 16) | ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == rfc::H2_FRAME_RST_STREAM && f_sid == stream_id {
            return true;
        }
        p += 9 + (f_len as i64);
    }
    return false;
}

fn test_h2_multiplexer_rfc9113_invariants(t: lit::T&) {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);

    t.run("H2 ingress rejects Content-Length > 0 on HEADERS frame with END_STREAM") { sub =>
        sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // HEADERS frame on stream 1 with END_STREAM set, but Content-Length: 10!
        var hpack_block: u8[>..] = [];
        var dt = internal::new_dynamic_table(4096);
        internal::encode_hpack_field(dt, hpack_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":path", "/api", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, "content-length", "10", internal::HpackIndexing.Incremental, false);

        let flags = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM;
        let hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      flags,
            stream_id:  1,
        };
        internal::encode_frame_header_to(hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);

        // Under RFC 9113 §8.1.1, Content-Length mismatch on END_STREAM MUST be rejected with stream error RST_STREAM
        sub.assert_true(ok, "Connection MUST remain alive on stream error per RFC 9113 §5.4.2");
        sub.assert_true(has_rst_stream_for(out_wire[..], 1), "Content-Length: 10 with 0 DATA bytes must emit RST_STREAM(PROTOCOL_ERROR)");
    };

    t.run("H2 ingress rejects PADDED frame when pad_len >= frame_payload.len") { sub =>
        sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // PADDED frame with payload length 5, but pad_len byte = 10 (pad_len >= payload_len)
        let hdr = internal::FrameHeader {
            length:     5,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_PADDED,
            stream_id:  1,
        };
        internal::encode_frame_header_to(hdr, wire_in);
        wire_in.push(10); // pad_len byte = 10
        wire_in.push(0); wire_in.push(0); wire_in.push(0); wire_in.push(0);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Padding length >= frame payload length MUST emit GOAWAY(PROTOCOL_ERROR)");
    };

    t.run("H2 ingress rejects request missing mandatory pseudo-headers") { sub =>
        sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // HEADERS frame missing :path and :scheme
        var hpack_block: u8[>..] = [];
        var dt = internal::new_dynamic_table(4096);
        internal::encode_hpack_field(dt, hpack_block, ":method", "GET", internal::HpackIndexing.Incremental, false);

        let flags = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM;
        let hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      flags,
            stream_id:  1,
        };
        internal::encode_frame_header_to(hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_true(ok, "Connection MUST remain alive on stream error per RFC 9113 §5.4.2");
        sub.assert_true(has_rst_stream_for(out_wire[..], 1), "Request missing :scheme and :path MUST emit RST_STREAM(PROTOCOL_ERROR)");
    };
}

// --- Component: regress_issues_batch14 ---
// Phase 14 RED test suite: RFC Protocol Invariants, Trailer Filtering,
// UTF-8 Truncation Boundaries, Sticky FSM Error States, and Codec Quota Guards.
//
// 1. HTTP/2 Response Trailers Filtering & HPACK Encoding (server/h2_multiplexer.goose)
// 2. WebSocket Close UTF-8 Boundary Truncation & Subprotocol Lists (realtime/websocket.goose)
// 3. HTTP Chunked 64-bit FSM Error Stickiness, Bare CR & Trailer Invariants (http/headers/chunked_fsm.goose)
// 4. Zstandard RFC 8878 RLE Block, SizeMismatch & 0-Sequence Bomb Guards (core/compress/zstd.goose)
// 5. Deflate RFC 1951 Dynamic Huffman Missing EOB 256 Rejection (core/compress/deflate.goose)

// ----------------------------------------------------------------------------
// 53. HTTP/2 Response Trailers Filtering & HPACK Encoding
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_trailers(t: lit::T&) {
    t.run("emit_response_trailers filters pseudo-headers, hop-by-hop, and disallowed fields") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var trailers = wing::HeaderMap { .. };

        // Valid trailers
        wing::append_header(trailers, "x-checksum", "sha256-abc");
        wing::append_header(trailers, "x-duration", "15ms");

        // Forbidden pseudo-headers and connection headers per RFC 9113 §8.1 / §8.2.2
        wing::append_header(trailers, ":status", "200");
        wing::append_header(trailers, "connection", "close");
        wing::append_header(trailers, "transfer-encoding", "chunked");
        wing::append_header(trailers, "content-length", "42");
        wing::append_header(trailers, "host", "example.com");

        var out_wire: u8[>..] = [];
        internal::emit_response_trailers(sess, 1, trailers, out_wire);

        sub.assert_gt(out_wire.len, 9, "Trailers frame emitted");

        // Parse frame header
        let hdr, ok_hdr = internal::parse_frame_header(out_wire[..9], 16384);
        sub.assert_eq(ok_hdr, rfc::H2_ERR_NO_ERROR, "Frame header valid");
        sub.assert_eq(hdr.frame_type, rfc::H2_FRAME_HEADERS, "Type is HEADERS");
        sub.assert_eq(hdr.stream_id, 1, "Stream ID is 1");
        sub.assert_true((hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0, "FLAG_END_HEADERS set");
        sub.assert_true((hdr.flags & rfc::H2_FLAG_END_STREAM) != 0, "FLAG_END_STREAM set");

        // Decode HPACK payload
        var dec_pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
        var dec_list = wing::HeaderMap { .. };
        let dec_err = internal::decode_hpack_to_map(sess.conn.hpack_dec, out_wire[9..9 + (hdr.length as i64)], dec_pseudo, dec_list);
        sub.assert_eq(dec_err, rfc::H2_ERR_NO_ERROR, "HPACK block decoded");

        // Exactly 2 valid trailer headers should survive
        sub.assert_eq(dec_list.entries.len, 2, "Only 2 valid trailers encoded");
        sub.assert_bytes_eq(wing::entry_name(dec_list, dec_list.entries[0]), "x-checksum", "First trailer name");
        sub.assert_bytes_eq(wing::entry_value(dec_list, dec_list.entries[0]), "sha256-abc", "First trailer value");
        sub.assert_bytes_eq(wing::entry_name(dec_list, dec_list.entries[1]), "x-duration", "Second trailer name");
        sub.assert_bytes_eq(wing::entry_value(dec_list, dec_list.entries[1]), "15ms", "Second trailer value");
    };

    t.run("handle_h2_server_ingress emits response with body and trailers") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // Client request on stream 1
        var hpack_block: u8[>..] = [];
        var dt = internal::new_dynamic_table(4096);
        internal::encode_hpack_field(dt, hpack_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":path", "/test", internal::HpackIndexing.Incremental, false);

        let req_hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        internal::encode_frame_header_to(req_hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_true(ok, "Ingress handled cleanly");
        sub.assert_gt(consumed, 0, "Ingress bytes consumed");
        sub.assert_gt(out_wire.len, 0, "Server produced response");
    };
}

// ----------------------------------------------------------------------------
// 54. HTTP/2 HPACK Host Syntax & Case-Insensitive Authority Equivalence
// ----------------------------------------------------------------------------
fn test_h2_hpack_host_authority_validation(t: lit::T&) {
    t.run("HPACK: reject empty :authority and empty host") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // 1. Empty :authority (0x01 is static index for :authority with literal value len 0)
        var empty_auth_block: u8[..32] = [];
        empty_auth_block.push(0x82); // :method: GET
        empty_auth_block.push(0x87); // :scheme: https
        empty_auth_block.push(0x84); // :path: /
        empty_auth_block.push(0x01); // literal with static name 1 (:authority)
        empty_auth_block.push(0x00); // value len 0

        let err_auth = internal::decode_hpack_to_map(dt, empty_auth_block[..], pseudo, out_list);
        sub.assert_eq(err_auth, rfc::H2_ERR_PROTOCOL_ERROR, "empty :authority MUST return PROTOCOL_ERROR");

        // 2. Empty host
        var empty_host_block: u8[..32] = [];
        empty_host_block.push(0x82); // :method: GET
        empty_host_block.push(0x87); // :scheme: https
        empty_host_block.push(0x84); // :path: /
        empty_host_block.push(0x00); // literal with new name
        empty_host_block.push(4);    // name len 4
        empty_host_block.append("host");
        empty_host_block.push(0);    // value len 0

        var pseudo2 = internal::H2PseudoHeaders { .. };
        var out_list2 = wing::HeaderMap { .. };
        let err_host = internal::decode_hpack_to_map(dt, empty_host_block[..], pseudo2, out_list2);
        sub.assert_eq(err_host, rfc::H2_ERR_PROTOCOL_ERROR, "empty host header MUST return PROTOCOL_ERROR");
    };

    t.run("HPACK: reject host with invalid authority characters") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // Host containing slash (host: evil.com/path)
        var slash_host_block: u8[..32] = [];
        slash_host_block.push(0x82); // :method: GET
        slash_host_block.push(0x87); // :scheme: https
        slash_host_block.push(0x84); // :path: /
        slash_host_block.push(0x00); // literal with new name
        slash_host_block.push(4);    // name len 4
        slash_host_block.append("host");
        slash_host_block.push(13);   // value len 13
        slash_host_block.append("evil.com/path");

        let err_slash = internal::decode_hpack_to_map(dt, slash_host_block[..], pseudo, out_list);
        sub.assert_eq(err_slash, rfc::H2_ERR_PROTOCOL_ERROR, "host with slash MUST return PROTOCOL_ERROR");

        // Host containing userinfo @ (host: user@evil.com)
        var user_host_block: u8[..32] = [];
        user_host_block.push(0x82);
        user_host_block.push(0x87);
        user_host_block.push(0x84);
        user_host_block.push(0x00);
        user_host_block.push(4);
        user_host_block.append("host");
        user_host_block.push(13);
        user_host_block.append("user@evil.com");

        var pseudo2 = internal::H2PseudoHeaders { .. };
        var out_list2 = wing::HeaderMap { .. };
        let err_user = internal::decode_hpack_to_map(dt, user_host_block[..], pseudo2, out_list2);
        sub.assert_eq(err_user, rfc::H2_ERR_PROTOCOL_ERROR, "host with @ MUST return PROTOCOL_ERROR");
    };

    t.run("HPACK: accept case-insensitive matching :authority and host") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // :authority: Example.COM and host: example.com
        var hpack_block: u8[..64] = [];
        hpack_block.push(0x82); // :method: GET
        hpack_block.push(0x87); // :scheme: https
        hpack_block.push(0x84); // :path: /
        hpack_block.push(0x01); // :authority
        hpack_block.push(11);
        hpack_block.append("Example.COM");
        hpack_block.push(0x00); // host
        hpack_block.push(4);
        hpack_block.append("host");
        hpack_block.push(11);
        hpack_block.append("example.com");

        let err = internal::decode_hpack_to_map(dt, hpack_block[..], pseudo, out_list);
        sub.assert_eq(err, rfc::H2_ERR_NO_ERROR, "case-insensitive matching authority and host MUST succeed");
    };
}

// ----------------------------------------------------------------------------
// 55. HTTP/2 Connection Frame Coordinator Trailer END_STREAM Enforcement
// ----------------------------------------------------------------------------
fn test_h2_connection_trailers_end_stream_requirement(t: lit::T&) {
    t.run("H2 ingress: second HEADERS frame on stream MUST have FLAG_END_STREAM") { sub =>
        var conn = internal::new_h2_connection(0);

        // 1. Initial HEADERS frame on stream 1 (without END_STREAM) -> opens stream
        let h_initial = internal::FrameHeader {
            length:     16,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS, // no END_STREAM
            stream_id:  1,
        };
        let err1 = internal::on_ingress_frame_header(conn, h_initial, 0);
        sub.assert_eq(err1, rfc::H2_ERR_NO_ERROR, "initial HEADERS frame accepted");

        // 2. Second HEADERS frame on stream 1 WITHOUT FLAG_END_STREAM (non-final trailers)
        // Per RFC 9113 §8.1: A HEADERS frame for trailers MUST carry FLAG_END_STREAM.
        let h_second_bad = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS, // no END_STREAM!
            stream_id:  1,
        };
        let err2 = internal::on_ingress_frame_header(conn, h_second_bad, 0);
        sub.assert_eq(err2, rfc::H2_ERR_PROTOCOL_ERROR, "second HEADERS without END_STREAM MUST trigger PROTOCOL_ERROR");
    };

    t.run("H2 ingress: valid trailers accepted, third HEADERS rejected") { sub =>
        var conn = internal::new_h2_connection(0);

        let h_initial = internal::FrameHeader {
            length:     16,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        internal::on_ingress_frame_header(conn, h_initial, 0);

        // Valid trailer frame with END_STREAM
        let h_trailers = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        let err_tr = internal::on_ingress_frame_header(conn, h_trailers, 0);
        sub.assert_eq(err_tr, rfc::H2_ERR_NO_ERROR, "valid trailers with END_STREAM accepted");

        // Third HEADERS frame after trailers received MUST be rejected
        let h_third = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        let err3 = internal::on_ingress_frame_header(conn, h_third, 0);
        sub.assert_true(err3 == rfc::H2_ERR_STREAM_CLOSED || err3 == rfc::H2_ERR_PROTOCOL_ERROR, "third HEADERS after trailers rejected");
    };
}

// ----------------------------------------------------------------------------
// 56. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition
// ----------------------------------------------------------------------------
fn test_h2_status_pseudo_header_validation(t: lit::T&) {
    t.run("HPACK: reject invalid :status values (out of range, non-3-digit, or 101)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };

        // 1. :status = "999" (out of 100..599 range)
        var block_999: u8[..32] = [];
        block_999.push(0x00); // literal with new name
        block_999.push(7);
        block_999.append(":status");
        block_999.push(3);
        block_999.append("999");

        let err_999 = internal::decode_hpack_to_map(dt, block_999[..], pseudo, out_list);
        sub.assert_eq(err_999, rfc::H2_ERR_PROTOCOL_ERROR, ":status 999 MUST return PROTOCOL_ERROR");

        // 2. :status = "042" (out of 100..599 range)
        var block_042: u8[..32] = [];
        block_042.push(0x00);
        block_042.push(7);
        block_042.append(":status");
        block_042.push(3);
        block_042.append("042");

        var pseudo2 = internal::H2PseudoHeaders { .. };
        var out_list2 = wing::HeaderMap { .. };
        let err_042 = internal::decode_hpack_to_map(dt, block_042[..], pseudo2, out_list2);
        sub.assert_eq(err_042, rfc::H2_ERR_PROTOCOL_ERROR, ":status 042 MUST return PROTOCOL_ERROR");

        // 3. :status = "101" (RFC 9113 §8.8: 101 Switching Protocols forbidden in HTTP/2)
        var block_101: u8[..32] = [];
        block_101.push(0x00);
        block_101.push(7);
        block_101.append(":status");
        block_101.push(3);
        block_101.append("101");

        var pseudo3 = internal::H2PseudoHeaders { .. };
        var out_list3 = wing::HeaderMap { .. };
        let err_101 = internal::decode_hpack_to_map(dt, block_101[..], pseudo3, out_list3);
        sub.assert_eq(err_101, rfc::H2_ERR_PROTOCOL_ERROR, ":status 101 MUST return PROTOCOL_ERROR");

        // 4. :status = "20" (less than 3 digits)
        var block_short: u8[..32] = [];
        block_short.push(0x00);
        block_short.push(7);
        block_short.append(":status");
        block_short.push(2);
        block_short.append("20");

        var pseudo4 = internal::H2PseudoHeaders { .. };
        var out_list4 = wing::HeaderMap { .. };
        let err_short = internal::decode_hpack_to_map(dt, block_short[..], pseudo4, out_list4);
        sub.assert_eq(err_short, rfc::H2_ERR_PROTOCOL_ERROR, ":status 20 MUST return PROTOCOL_ERROR");

        // 5. :status = "2000" (more than 3 digits)
        var block_long: u8[..32] = [];
        block_long.push(0x00);
        block_long.push(7);
        block_long.append(":status");
        block_long.push(4);
        block_long.append("2000");

        var pseudo5 = internal::H2PseudoHeaders { .. };
        var out_list5 = wing::HeaderMap { .. };
        let err_long = internal::decode_hpack_to_map(dt, block_long[..], pseudo5, out_list5);
        sub.assert_eq(err_long, rfc::H2_ERR_PROTOCOL_ERROR, ":status 2000 MUST return PROTOCOL_ERROR");
    };

    t.run("HPACK: accept valid 3-digit :status values") { sub =>
        var dt = internal::new_dynamic_table(4096);

        // :status = "200"
        var block_200: u8[..16] = [];
        block_200.push(0x88); // static entry 8 (:status: 200)

        var pseudo = internal::H2PseudoHeaders { .. };
        var out_list = wing::HeaderMap { .. };
        let err_200 = internal::decode_hpack_to_map(dt, block_200[..], pseudo, out_list);
        sub.assert_eq(err_200, rfc::H2_ERR_NO_ERROR, ":status 200 accepted");

        // :status = "204"
        var block_204: u8[..16] = [];
        block_204.push(0x89); // static entry 9 (:status: 204)

        var pseudo2 = internal::H2PseudoHeaders { .. };
        var out_list2 = wing::HeaderMap { .. };
        let err_204 = internal::decode_hpack_to_map(dt, block_204[..], pseudo2, out_list2);
        sub.assert_eq(err_204, rfc::H2_ERR_NO_ERROR, ":status 204 accepted");
    };
}

// ----------------------------------------------------------------------------
// 57. HTTP/2 DATA Frame Rejection on Streams with Trailers Received
// ----------------------------------------------------------------------------
fn test_h2_data_frame_after_trailers_rejection(t: lit::T&) {
    t.run("H2: reject DATA frame on stream where trailers were received") { sub =>
        var conn = internal::new_h2_connection(0);

        // Open stream 1
        let h_initial = internal::FrameHeader {
            length:     16,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        internal::on_ingress_frame_header(conn, h_initial, 0);

        // Receive trailers with END_STREAM
        let h_trailers = internal::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        let err_tr = internal::on_ingress_frame_header(conn, h_trailers, 0);
        sub.assert_eq(err_tr, rfc::H2_ERR_NO_ERROR, "trailers accepted");

        // Now attempt to feed a DATA frame on stream 1
        let h_data = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      0,
            stream_id:  1,
        };
        let err_data = internal::on_data_frame_received(conn, h_data, 10);
        sub.assert_eq(err_data, rfc::H2_ERR_STREAM_CLOSED, "DATA frame after trailers MUST return ERR_STREAM_CLOSED");
    };
}

// ----------------------------------------------------------------------------
// 58. goose2rfc HTTP/2 & HPACK Audit Regressions
// ----------------------------------------------------------------------------
fn test_h2_goose2rfc_audit_regressions(t: lit::T&) {
    t.run("H2_1_C01: PUSH_PROMISE requires odd Open/HalfClosedLocal parent stream (RFC 9113 §6.6)") { sub =>
        var conn = internal::new_h2_connection(0);
        conn.is_server = false;
        conn.enable_push = true;
        internal::open_new_session_stream(conn, 1, true);

        let h_pp = internal::FrameHeader {
            length:     12,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let err_pp = internal::on_ingress_frame_header(conn, h_pp, 0);
        sub.assert_eq(err_pp, rfc::H2_ERR_PROTOCOL_ERROR, "PUSH_PROMISE on HalfClosedRemote stream rejected");

        let h_pp_even = internal::FrameHeader {
            length:     12,
            frame_type: rfc::H2_FRAME_PUSH_PROMISE,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  2,
        };
        let err_even = internal::on_ingress_frame_header(conn, h_pp_even, 0);
        sub.assert_eq(err_even, rfc::H2_ERR_PROTOCOL_ERROR, "PUSH_PROMISE on even stream ID rejected");
    };

    t.run("H2_1_C03 & H2_1_C05: PRIORITY_UPDATE on stream 0/even and closed stream monotonicity") { sub =>
        var conn = internal::new_h2_connection(0);
        let p = wing::PriorityParam { urgency: 1, incremental: true };
        let err_zero = internal::apply_priority_update(conn, 0, p);
        sub.assert_eq(err_zero, rfc::H2_ERR_PROTOCOL_ERROR, "PRIORITY_UPDATE prioritized_stream_id=0 rejected");
        sub.assert_true(!conn.client_sent_priority, "client_sent_priority not dirtied on error");

        let err_even = internal::apply_priority_update(conn, 4, p);
        sub.assert_eq(err_even, rfc::H2_ERR_PROTOCOL_ERROR, "PRIORITY_UPDATE on idle even push stream rejected");

        // Open stream 5 -> stream 3 is implicitly closed (RFC 9113 §5.1.1)
        let h_open5 = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  5,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, h_open5, 0), rfc::H2_ERR_NO_ERROR, "open stream 5");

        let h_rst3 = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_RST_STREAM,
            flags:      0,
            stream_id:  3,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn, h_rst3, 0), rfc::H2_ERR_NO_ERROR, "RST_STREAM on implicitly closed stream 3 allowed");

        let err_win7 = internal::apply_window_update(conn, 7, 1024);
        sub.assert_eq(err_win7, rfc::H2_ERR_PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream 7 > last_peer_stream_id rejected");

        let err_win3 = internal::apply_window_update(conn, 3, 1024);
        sub.assert_eq(err_win3, rfc::H2_ERR_NO_ERROR, "WINDOW_UPDATE on implicitly closed stream 3 ignored per §6.9");
    };

    t.run("H2_1_C08: ALTSVC origin/stream validation & transactional rollback (RFC 7838 §4)") { sub =>
        var out: u8[..64] = [];
        out.append("KEEP");
        let ok_both = internal::encode_altsvc_frame(out, "https://example.com", "h2=\":443\"", 1);
        sub.assert_true(!ok_both, "ALTSVC with non-zero stream_id and non-empty origin rejected");
        sub.assert_eq(out.len, 4, "out rolled back on invalid ALTSVC");

        let ok_empty_val = internal::encode_altsvc_frame(out, "", "", 1);
        sub.assert_true(!ok_empty_val, "ALTSVC with empty Alt-Svc-Field-Value rejected");
        sub.assert_eq(out.len, 4, "out untouched on empty alt_svc_val");

        var raw_empty: u8[..16] = [];
        raw_empty.push(0);
        raw_empty.push(4);
        raw_empty.append("test");
        let parsed, err_parse = internal::parse_altsvc_frame(raw_empty[..], 0);
        sub.assert_eq(err_parse, rfc::H2_ERR_NO_ERROR, "ALTSVC frame with empty value ignored without connection error");
        sub.assert_eq(parsed.alt_svc_value.len, 0, "ALTSVC frame with empty value ignored");
    };

    t.run("H2_2_C03, H2_2_C05, H2_2_C06: HPACK pseudo-header syntax, TE in trailers, and rollback") { sub =>
        var pseudo = internal::H2PseudoHeaders { .. };
        var headers = wing::HeaderMap { .. };
        let err_m = internal::validate_and_record_pseudo_header(pseudo, ":method", "GET /Evil", true);
        sub.assert_eq(err_m, rfc::H2_ERR_PROTOCOL_ERROR, ":method with space rejected");

        var pseudo_s = internal::H2PseudoHeaders { .. };
        let err_s = internal::validate_and_record_pseudo_header(pseudo_s, ":scheme", "1http", true);
        sub.assert_eq(err_s, rfc::H2_ERR_PROTOCOL_ERROR, ":scheme starting with digit rejected");

        var pseudo_tr = internal::H2PseudoHeaders { is_trailer: true, .. };
        let err_te = internal::validate_header_ordering_and_rules(pseudo_tr, headers, "te", "trailers");
        sub.assert_eq(err_te, rfc::H2_ERR_PROTOCOL_ERROR, "TE header in trailers rejected (RFC 9113 §8.1.2)");
        sub.assert_true(!pseudo_tr.has_regular_header, "pseudo_tr rolled back on rejected trailer header");
    };
}

fn main() {
    var runner = lit::new_runner("HTTP/2 Protocol, Multiplexing, HPACK, and RFC Invariants Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. HPACK Huffman FSM & RFC 7541 Integer Codec", test_hpack_huffman_and_integer_codec);
    lit::run_case(runner, "2. HPACK Dynamic Table & Header Block Conformance", test_hpack_dynamic_table_and_header_blocks);
    lit::run_case(runner, "3. Binary Framing & RFC 9218 Extensible Prioritization", test_binary_framing_and_rfc9218);
    lit::run_case(runner, "4. Two-Level Signed Flow Control & Negative Windows", test_flow_control_and_session_state);
    lit::run_case(runner, "5. RFC 9218 Extensible Write Scheduler", test_rfc9218_write_scheduler);
    lit::run_case(runner, "6. Anti-DoS Engine & Resource Quota Protections", test_anti_dos_mitigations);
    lit::run_case(runner, "7. Preface, Handshake & Settings Negotiation", test_h2_handshake_and_settings);
    lit::run_case(runner, "8. Stream Multiplexing & Pipeline Dispatch", test_h2_request_dispatch);
    lit::run_case(runner, "9. HttpServer End-to-End HTTP/2 Integration", test_h2_server_wire_integration);
    lit::run_case(runner, "10. CONTINUATION Assembly, Anti-DoS & Rapid Reset", test_h2_continuation_and_anti_dos);
    lit::run_case(runner, "11. RFC 9113 Protocol Invariants & Zero-Allocation Ingress", test_h2_protocol_invariants);
    lit::run_case(runner, "12. CONTINUATION Flood & Interleaving Guard (CVE-2024-27983)", test_continuation_flood_and_interleaving);
    lit::run_case(runner, "13. Rapid Reset & Resource DoS Floods (CVE-2023-44487 & CVE-2019-9512)", test_rapid_reset_and_dos_floods);
    lit::run_case(runner, "14. SETTINGS & Stream ID Invariants", test_settings_and_stream_id_invariants);
    lit::run_case(runner, "15. Frame Header Parsing & Type Mapping (RFC 9113)", test_h2_wire_framing_and_types);
    lit::run_case(runner, "16. SETTINGS & PING Frame Wire Invariants (RFC 9113 §6.5/§6.7)", test_h2_settings_and_ping_invariants);
    lit::run_case(runner, "17. Flow Control Window Arithmetic & Overflow Guards (RFC 9113 §6.9)", test_h2_window_update_and_flow_control);
    lit::run_case(runner, "18. CONTINUATION Flood & Interleaving Defenses (RFC 9113 §4.3/§6.10)", test_h2_continuation_flood_and_interleaving);
    lit::run_case(runner, "19. HPACK Variable-Length Integer Codec Overflows (FIND-401)", test_hpack_integer_codec_overflows);
    lit::run_case(runner, "20. HPACK Dynamic Table Invariants, Eviction & Wrap-Around", test_hpack_dynamic_table_invariants);
    lit::run_case(runner, "21. RFC 9113 Header Block Security Rules & Invariants", test_hpack_rfc9113_header_block_rules);
    lit::run_case(runner, "22. Extended CONNECT Detection", test_extended_connect_detection);
    lit::run_case(runner, "23. H3 WebSocket Formatting & Validation", test_h3_websocket_formatting);
    lit::run_case(runner, "24. H3 Server Upgrade (200 OK)", test_h3_server_upgrade);
    lit::run_case(runner, "25. Stream Frame Encapsulation", test_stream_frame_encapsulation);
    lit::run_case(runner, "26. Priority Parsing", test_priority_parsing);
    lit::run_case(runner, "27. Priority Serialization", test_priority_serialization);
    lit::run_case(runner, "28. H2 Priority Update Frame", test_h2_priority_update_frame);
    lit::run_case(runner, "29. H3 Priority Update Integration", test_h3_priority_update_integration);
    lit::run_case(runner, "30. HTTP/2 FRAME_ORIGIN & FRAME_ALTSVC (RFC 8336 & RFC 7838)", test_h2_extension_frames);
    lit::run_case(runner, "31. nghttp2 & h2 Vendor Conformance Vectors", test_nghttp2_and_h2_vendor_conformance);
    lit::run_case(runner, "32. nghttp2 Session, Mandatory Headers & Flow Control Semantics", test_nghttp2_session_and_http_semantics);
    lit::run_case(runner, "33. F015 H2 Continuation, Dict, Forwarded & Tracestate", test_f015_h2_dict_forwarded_hsts_trace);
    lit::run_case(runner, "34. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters", test_h2_field_value_ctl_rejection);
    lit::run_case(runner, "35. RFC 9113 §8.3: Undefined Pseudo-Headers Rejection", test_h2_undefined_pseudo_header_rejection);
    lit::run_case(runner, "36. RFC 9113 §6.6: Frame Rules for PUSH_PROMISE", test_h2_push_promise_frame_rules);
    lit::run_case(runner, "37. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Stream ID Invariant", test_h2_goaway_stream_id_zero);
    lit::run_case(runner, "38. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present", test_h2_connect_scheme_path_rejection);
    lit::run_case(runner, "39. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = '*' ONLY for OPTIONS", test_h2_asterisk_path_only_for_options);
    lit::run_case(runner, "40. RFC 9113 §8.3: Request and Response Pseudo-Header Segregation", test_h2_pseudo_header_request_response_segregation);
    lit::run_case(runner, "41. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicates", test_h2_authority_host_consistency_and_duplicates);
    lit::run_case(runner, "42. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant", test_h2_goaway_last_stream_id_peer_role);
    lit::run_case(runner, "43. RFC 9113 §6.8 & Go #82365: HTTP/2 Inbound Stream Rejection After GOAWAY", test_h2_stream_blocked_after_goaway);
    lit::run_case(runner, "44. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header Character Validation", test_h2_path_character_validation);
    lit::run_case(runner, "45. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers", test_h2_trailer_forbidden_pseudo_headers);
    lit::run_case(runner, "46. RFC 9113 §8.3.1 & uWS #1949: HTTP/2 :authority Forbidden Characters", test_h2_authority_character_validation);
    lit::run_case(runner, "47. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields", test_h2_trailer_disallowed_fields);
    lit::run_case(runner, "48. RFC 9113 §6.5.2: HTTP/2 Client SETTINGS Frame Rejection of SETTINGS_ENABLE_PUSH != 0", test_h2_client_settings_enable_push_rejection);
    lit::run_case(runner, "49. HPACK literal header indexed name dynamic value overflow (http2/hpack.goose)", test_hpack_literal_indexed_name_dynamic_value_overflow);
    lit::run_case(runner, "50. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)", test_h2_authority_whitespace_rejection);
    lit::run_case(runner, "51. H2 multiplexer & HPACK RFC 9113 (server/*, http2/*, http/*)", test_h2_multiplexer_and_hpack_rfc9113);
    lit::run_case(runner, "52. H2 multiplexer RFC 9113 invariants (server/h2_multiplexer.goose)", test_h2_multiplexer_rfc9113_invariants);
    lit::run_case(runner, "53. H2 multiplexer trailer encoding (server/h2_multiplexer.goose)", test_h2_multiplexer_trailers);
    lit::run_case(runner, "54. HTTP/2 HPACK Host Syntax & Case-Insensitive Authority Equivalence", test_h2_hpack_host_authority_validation);
    lit::run_case(runner, "55. HTTP/2 Connection Frame Coordinator Trailer END_STREAM Enforcement", test_h2_connection_trailers_end_stream_requirement);
    lit::run_case(runner, "56. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition", test_h2_status_pseudo_header_validation);
    lit::run_case(runner, "57. HTTP/2 DATA Frame Rejection on Streams with Trailers Received", test_h2_data_frame_after_trailers_rejection);
    lit::run_case(runner, "58. goose2rfc HTTP/2 & HPACK Audit Regressions", test_h2_goose2rfc_audit_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
