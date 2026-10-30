// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP/2 Protocol, Multiplexing, HPACK, and RFC Invariants Suite
import std;
import core from "..";
import wing from "..";

// --- Component: http2_suite ---
// HTTP/2 Echelon 6 Conformance & Reference Suite (RFC 7541, RFC 9113, RFC 9218).
// Tests HPACK Huffman FSM, Zero-Allocation Dynamic Table, Binary Framing,
// Two-Level Signed Flow Control, RFC 9218 Write Scheduler, and Anti-DoS Defenses.

// 1. HPACK Huffman FSM & RFC 7541 Integer Codec Tests
fn test_hpack_huffman_and_integer_codec(t: core::T&) {
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
fn test_hpack_dynamic_table_and_header_blocks(t: core::T&) {
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
        var val_buf: u8[..64] = [];
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
        var out = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, internal::ERR_NO_ERROR, "valid pseudo-headers decode with NO_ERROR");
        sub.assert_eq(out.fields.len, 3, "3 fields decoded");
        sub.assert_eq(out.fields[0].name[..], ":method", "method field");
        sub.assert_eq(out.fields[0].value[..], "GET", "GET value");
    };

    t.run("DYN-04: Pseudo-Header Ordering Violation Rejection (RFC 9113 Section 8.3)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Block:
        // 1. Regular header: accept: */* (static index 19 -> 0x93)
        // 2. Pseudo header: :path: / (static index 4 -> 0x84)  <-- ILLEGAL: pseudo after regular!
        let raw_block: u8[2] = [0x93, 0x84];
        var out = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "pseudo-header after regular header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-05: Duplicate Pseudo-Header Rejection") { sub =>
        var dt = internal::new_dynamic_table(4096);
        // Block: duplicate :method: GET (0x82, 0x82)
        let raw_block: u8[2] = [0x82, 0x82];
        var out = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "duplicate pseudo-header must trigger PROTOCOL_ERROR");
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

        var out = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "conflicting Content-Length headers must trigger PROTOCOL_ERROR");

        // Identical matching Content-Length: "10" and "10" must be accepted
        raw_block.clear();
        raw_block.push(0x83); // :method: POST
        raw_block.push(0x87); // :scheme: https
        raw_block.push(0x84); // :path: /
        raw_block.push(0x00); raw_block.push(14); raw_block.append("content-length"); raw_block.push(2); raw_block.append("10");
        raw_block.push(0x00); raw_block.push(14); raw_block.append("content-length"); raw_block.push(2); raw_block.append("10");

        var out_ok = internal::DecodedH2HeaderList { .. };
        let err_ok = internal::decode_hpack_header_block(dt, raw_block[..], out_ok);
        sub.assert_eq(err_ok, internal::ERR_NO_ERROR, "identical multiple Content-Length headers are accepted");
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

        var out = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "forbidden 'connection' header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-08: Missing Mandatory Pseudo-Headers Rejection (RFC 9113 §8.3.1)") { sub =>
        var dt = internal::new_dynamic_table(4096);

        // Missing :path (only :method: GET and :scheme: https)
        let block_no_path: u8[2] = [0x82, 0x87];
        var out1 = internal::DecodedH2HeaderList { .. };
        let err1 = internal::decode_hpack_header_block(dt, block_no_path[..], out1);
        sub.assert_eq(err1, internal::ERR_PROTOCOL_ERROR, "request without :path must trigger PROTOCOL_ERROR");

        // Missing all pseudo-headers (only regular header)
        var block_no_pseudo: u8[..32] = [];
        block_no_pseudo.push(0x00);
        block_no_pseudo.push(10);
        block_no_pseudo.append("user-agent");
        block_no_pseudo.push(3);
        block_no_pseudo.append("bot");
        var out2 = internal::DecodedH2HeaderList { .. };
        let err2 = internal::decode_hpack_header_block(dt, block_no_pseudo[..], out2);
        sub.assert_eq(err2, internal::ERR_PROTOCOL_ERROR, "request without pseudo-headers must trigger PROTOCOL_ERROR");
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
fn test_binary_framing_and_rfc9218(t: core::T&) {
    t.run("FRAME-01: 9-Byte Frame Header Codec Roundtrip") { sub =>
        let orig_hdr = internal::FrameHeader {
            length: 16384,
            frame_type: internal::FRAME_DATA,
            flags: internal::FLAG_END_STREAM,
            stream_id: 101,
        };

        var buf: u8[9] = [0; 9];
        internal::encode_frame_header(orig_hdr, buf);
        sub.assert_eq(buf.len, 9, "frame header is exactly 9 bytes");

        let parsed_hdr, err = internal::parse_frame_header(buf[..]);
        sub.assert_eq(err, internal::ERR_NO_ERROR, "parse_frame_header succeeds");
        sub.assert_eq(parsed_hdr.length, 16384, "payload length matches");
        sub.assert_eq(parsed_hdr.frame_type, internal::FRAME_DATA, "frame type matches");
        sub.assert_eq(parsed_hdr.flags, internal::FLAG_END_STREAM, "flags match");
        sub.assert_eq(parsed_hdr.stream_id, 101, "stream id matches");
    };

    t.run("FRAME-02: PADDED Payload Extraction") { sub =>
        let hdr = internal::FrameHeader {
            length: 12,
            frame_type: internal::FRAME_DATA,
            flags: internal::FLAG_PADDED,
            stream_id: 1,
        };
        // Payload: 1 byte pad length (3), 8 bytes data, 3 bytes padding
        let payload: u8[12] = [
            0x03,                                           // Pad length: 3
            'h', 'e', 'l', 'l', 'o', '!', '!', '!',         // 8 bytes data
            0x00, 0x00, 0x00,                               // 3 bytes padding
        ];

        let unpadded, err = internal::extract_padded_frame_payload(hdr, payload[..]);
        sub.assert_eq(err, internal::ERR_NO_ERROR, "extract padding succeeds");
        sub.assert_eq(unpadded.len, 8, "unpadded length is 8");
        sub.assert_eq(unpadded, "hello!!!", "unpadded data intact");

        // Invalid padding length: pad_len (15) > length (12) -> PROTOCOL_ERROR
        let bad_payload: u8[12] = [0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let _, bad_err = internal::extract_padded_frame_payload(hdr, bad_payload[..]);
        sub.assert_eq(bad_err, internal::ERR_PROTOCOL_ERROR, "oversized padding triggers PROTOCOL_ERROR");
    };

    t.run("FRAME-03: RFC 9218 Priority Dictionary Parser") { sub =>
        // Vector 1: "u=0, i"
        let p1, ok1 = wing::parse_priority_param_rfc9218("u=0, i");
        sub.assert_true(ok1, "parse u=0, i succeeds");
        sub.assert_eq(p1.urgency, 0, "urgency is 0");
        sub.assert_true(p1.incremental, "incremental is true");

        // Vector 2: "u=5"
        let p2, ok2 = wing::parse_priority_param_rfc9218("u=5");
        sub.assert_true(ok2, "parse u=5 succeeds");
        sub.assert_eq(p2.urgency, 5, "urgency is 5");
        sub.assert_false(p2.incremental, "incremental defaults to false");

        // Vector 3: "i=?0, u=2"
        let p3, ok3 = wing::parse_priority_param_rfc9218("i=?0, u=2");
        sub.assert_true(ok3, "parse i=?0, u=2 succeeds");
        sub.assert_eq(p3.urgency, 2, "urgency is 2");
        sub.assert_false(p3.incremental, "incremental is explicitly false");

        // Vector 4: Forward compatibility - ignore unknown parameters
        let p4, ok4 = wing::parse_priority_param_rfc9218("future_param=123, u=7");
        sub.assert_true(ok4, "parse with unknown param succeeds");
        sub.assert_eq(p4.urgency, 7, "urgency is 7");
    };

    t.run("FRAME-04: PRIORITY_UPDATE Frame Codec Roundtrip") { sub =>
        let prio = wing::PriorityParam { urgency: 1, incremental: true };
        var payload: u8[..32] = [];
        internal::encode_priority_update_payload(42, prio, payload);

        let stream_id, parsed_prio, err = internal::parse_priority_update_payload(payload[..]);
        sub.assert_eq(err, internal::ERR_NO_ERROR, "parse_priority_update succeeds");
        sub.assert_eq(stream_id, 42, "stream id matches 42");
        sub.assert_eq(parsed_prio.urgency, 1, "urgency matches 1");
        sub.assert_true(parsed_prio.incremental, "incremental is true");
    };

    t.run("FRAME-05: SETTINGS Parameter Boundary Validation") { sub =>
        // MAX_FRAME_SIZE below 16384 -> PROTOCOL_ERROR
        sub.assert_eq(internal::validate_settings_parameter(internal::SETTING_MAX_FRAME_SIZE, 1000), internal::ERR_PROTOCOL_ERROR);
        // MAX_FRAME_SIZE above 16777215 -> PROTOCOL_ERROR
        sub.assert_eq(internal::validate_settings_parameter(internal::SETTING_MAX_FRAME_SIZE, 20000000), internal::ERR_PROTOCOL_ERROR);
        // Valid MAX_FRAME_SIZE 65536 -> NO_ERROR
        sub.assert_eq(internal::validate_settings_parameter(internal::SETTING_MAX_FRAME_SIZE, 65536), internal::ERR_NO_ERROR);

        // INITIAL_WINDOW_SIZE > 0x7FFFFFFF -> FLOW_CONTROL_ERROR
        sub.assert_eq(internal::validate_settings_parameter(internal::SETTING_INITIAL_WINDOW_SIZE, 0x80000000), internal::ERR_FLOW_CONTROL_ERROR);

        // ENABLE_PUSH must be 0 or 1
        sub.assert_eq(internal::validate_settings_parameter(internal::SETTING_ENABLE_PUSH, 2), internal::ERR_PROTOCOL_ERROR);
        sub.assert_eq(internal::validate_settings_parameter(internal::SETTING_ENABLE_PUSH, 1), internal::ERR_NO_ERROR);
    };
}

// 4. Two-Level Signed Flow Control & Negative Window Invariant Tests
fn test_flow_control_and_session_state(t: core::T&) {
    t.run("FLOW-01: Signed Window Deltas & Negative Window State (RFC 9113 Section 6.9.2)") { sub =>
        var sess = internal::new_session_state();

        // 1. Open stream 1
        let hdr_open = internal::FrameHeader {
            length: 10,
            frame_type: internal::FRAME_HEADERS,
            flags: internal::FLAG_END_HEADERS,
            stream_id: 1,
        };
        let err_open = internal::on_ingress_frame_header(sess, hdr_open, 0);
        sub.assert_eq(err_open, internal::ERR_NO_ERROR, "open stream 1");
        sub.assert_eq(sess.streams[0].send_window, 65535, "initial send window is 65535");

        // 2. Peer decreases SETTINGS_INITIAL_WINDOW_SIZE from 65535 to 10000 (delta = -55535)
        let err_delta1 = internal::apply_peer_initial_window_size_delta(sess, 10000);
        sub.assert_eq(err_delta1, internal::ERR_NO_ERROR, "apply initial window delta 10000");
        sub.assert_eq(sess.streams[0].send_window, 10000, "stream window reduced to 10000");

        // 3. Peer decreases SETTINGS_INITIAL_WINDOW_SIZE by another 20000 to 0 (delta = -10000)
        // Then stream sends 5000 bytes so window is 5000, then delta brings it negative!
        sess.streams[0].send_window = 5000;
        let err_delta2 = internal::apply_peer_initial_window_size_delta(sess, 0);
        sub.assert_eq(err_delta2, internal::ERR_NO_ERROR, "initial window delta to 0");
        sub.assert_eq(sess.streams[0].send_window, -5000, "stream window is legitimately negative (-5000)");

        // 4. While stream send window is negative, effective quota must be 0
        let quota = internal::compute_stream_send_quota(sess, 1);
        sub.assert_eq(quota, 0, "quota with negative window is 0");

        // 5. WINDOW_UPDATE restores stream window to positive (+3000)
        let err_up = internal::apply_window_update(sess, 1, 8000);
        sub.assert_eq(err_up, internal::ERR_NO_ERROR, "window update +8000");
        sub.assert_eq(sess.streams[0].send_window, 3000, "stream window restored to +3000");

        let quota_restored = internal::compute_stream_send_quota(sess, 1);
        sub.assert_eq(quota_restored, 3000, "quota is now 3000");
    };

    t.run("FLOW-02: Window Update Overflow Rejection (Go #58456)") { sub =>
        var sess = internal::new_session_state();
        // Conn send window is 65535. Adding 0x7FFFFFFF will overflow > 2^31 - 1
        let err_ovf = internal::apply_window_update(sess, 0, 0x7FFFFFFF);
        sub.assert_eq(err_ovf, internal::ERR_FLOW_CONTROL_ERROR, "window update causing overflow must trigger FLOW_CONTROL_ERROR");

        // Window update with increment = 0 -> PROTOCOL_ERROR
        let err_zero = internal::apply_window_update(sess, 0, 0);
        sub.assert_eq(err_zero, internal::ERR_PROTOCOL_ERROR, "window update increment 0 must trigger PROTOCOL_ERROR");
    };
}

// 5. RFC 9218 Extensible Write Scheduler Tests
fn test_rfc9218_write_scheduler(t: core::T&) {
    t.run("SCHED-01: Urgency 0..7 Priority Ordering") { sub =>
        var sess = internal::new_session_state();

        // Open stream 1 (urgency 3 by default)
        let h1 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);

        // Open stream 3 (set to urgency 0 - urgent)
        let h3 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 3 };
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
        let h1 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);
        internal::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 1, incremental: false });
        sess.streams[0].pending_send_bytes = 2000;

        // Stream 3: urgency 1, incremental, 2000 bytes
        let h3 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 3 };
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
        let h1 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);
        internal::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 2, incremental: true });
        sess.streams[0].pending_send_bytes = 1000;

        // Stream 3: urgency 2, incremental, 1000 bytes
        let h3 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 3 };
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
        let h1 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);
        internal::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 0, incremental: false });
        sess.streams[0].pending_send_bytes = 20000;

        // Stream 3: lower urgency 3, non-incremental, small payload (500 bytes)
        let h3 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 3 };
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
fn test_anti_dos_mitigations(t: core::T&) {
    t.run("DOS-01: Rapid Reset Token Bucket Defense (CVE-2023-44487)") { sub =>
        // Session with small reset burst = 5
        var sess = internal::SessionState {
            reset_limiter: internal::new_h2_token_bucket(5, 1, 0),
            ..
        };

        // Open stream 1 then reset it
        let h_open = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h_open, 0);

        // Exhaust tokens (5 RST_STREAMs on stream 1)
        var i: u32 = 0;
        while i < 5 {
            let rst = internal::FrameHeader { length: 4, frame_type: internal::FRAME_RST_STREAM, flags: 0, stream_id: 1 };
            let err = internal::on_ingress_frame_header(sess, rst, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "allowed within burst limit");
            i++;
        }

        // 6th RST_STREAM without time advance -> ENHANCE_YOUR_CALM
        let rst_flood = internal::FrameHeader { length: 4, frame_type: internal::FRAME_RST_STREAM, flags: 0, stream_id: 1 };
        let err_flood = internal::on_ingress_frame_header(sess, rst_flood, 0);
        sub.assert_eq(err_flood, internal::ERR_ENHANCE_YOUR_CALM, "rapid reset flood must trigger ENHANCE_YOUR_CALM");
    };

    t.run("DOS-02: CONTINUATION Flood Guard (CVE-2024-28182)") { sub =>
        var sess = internal::new_session_state();

        // Initial HEADERS on stream 1 without END_HEADERS (enters ExpectContinuation)
        let h1 = internal::FrameHeader { length: 100, frame_type: internal::FRAME_HEADERS, flags: 0, stream_id: 1 };
        let err0 = internal::on_ingress_frame_header(sess, h1, 0);
        sub.assert_eq(err0, internal::ERR_NO_ERROR, "headers accepted");

        // Send MAX_CONT_FRAMES_LIMIT (16) CONTINUATION frames
        var i: u32 = 0;
        while i < internal::MAX_CONT_FRAMES_LIMIT {
            let c = internal::FrameHeader { length: 10, frame_type: internal::FRAME_CONTINUATION, flags: 0, stream_id: 1 };
            let err = internal::on_ingress_frame_header(sess, c, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "continuation within limit accepted");
            i++;
        }

        // 17th CONTINUATION frame -> ENHANCE_YOUR_CALM
        let c_flood = internal::FrameHeader { length: 10, frame_type: internal::FRAME_CONTINUATION, flags: 0, stream_id: 1 };
        let err_flood = internal::on_ingress_frame_header(sess, c_flood, 0);
        sub.assert_eq(err_flood, internal::ERR_ENHANCE_YOUR_CALM, "excess CONTINUATION frames trigger ENHANCE_YOUR_CALM");
    };

    t.run("DOS-03: Slow-Drip CONTINUATION Defense (CVE-2024-27983)") { sub =>
        var sess = internal::new_session_state(0, 8192);

        // Start CONTINUATION block at now_ms = 0
        let h1 = internal::FrameHeader { length: 10, frame_type: internal::FRAME_HEADERS, flags: 0, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);

        // Second CONTINUATION arrives after 15,000 ms (> 10,000 ms max_header_block_duration_ms)
        let c_slow = internal::FrameHeader { length: 10, frame_type: internal::FRAME_CONTINUATION, flags: 0, stream_id: 1 };
        let err_slow = internal::on_ingress_frame_header(sess, c_slow, 15000);
        sub.assert_eq(err_slow, internal::ERR_ENHANCE_YOUR_CALM, "slow-drip header block retention triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-04: Stream Interleaving Rejection During CONTINUATION (RFC 9113 Section 6.10)") { sub =>
        var sess = internal::new_session_state();

        // HEADERS on stream 1 expecting CONTINUATION
        let h1 = internal::FrameHeader { length: 10, frame_type: internal::FRAME_HEADERS, flags: 0, stream_id: 1 };
        internal::on_ingress_frame_header(sess, h1, 0);

        // Interleaved DATA frame on stream 1
        let d = internal::FrameHeader { length: 10, frame_type: internal::FRAME_DATA, flags: 0, stream_id: 1 };
        let err_d = internal::on_ingress_frame_header(sess, d, 0);
        sub.assert_eq(err_d, internal::ERR_PROTOCOL_ERROR, "interleaved DATA frame triggers PROTOCOL_ERROR");
    };

    t.run("DOS-05: Empty Frame Flooding Defense (CVE-2019-9518)") { sub =>
        var sess = internal::new_session_state();

        // Send 8 empty DATA frames without END_STREAM (allowed)
        var i: u32 = 0;
        while i < internal::MAX_EMPTY_FRAME_STREAK {
            let empty_data = internal::FrameHeader { length: 0, frame_type: internal::FRAME_DATA, flags: 0, stream_id: 1 };
            let err = internal::on_ingress_frame_header(sess, empty_data, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "empty frame streak within limit");
            i++;
        }

        // 9th empty DATA frame -> ENHANCE_YOUR_CALM
        let empty_streak = internal::FrameHeader { length: 0, frame_type: internal::FRAME_DATA, flags: 0, stream_id: 1 };
        let err_streak = internal::on_ingress_frame_header(sess, empty_streak, 0);
        sub.assert_eq(err_streak, internal::ERR_ENHANCE_YOUR_CALM, "empty frame flood streak triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-06: PING / SETTINGS Flood Defense (CVE-2019-9512 / CVE-2019-9515)") { sub =>
        var sess = internal::new_session_state();

        // Send 64 unacknowledged PING frames
        var i: u32 = 0;
        while i < internal::MAX_PENDING_CTRL_FRAMES {
            let ping = internal::FrameHeader { length: 8, frame_type: internal::FRAME_PING, flags: 0, stream_id: 0 };
            let err = internal::on_ingress_frame_header(sess, ping, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "ping within control frame quota");
            i++;
        }

        // 65th unacknowledged PING -> ENHANCE_YOUR_CALM
        let ping_flood = internal::FrameHeader { length: 8, frame_type: internal::FRAME_PING, flags: 0, stream_id: 0 };
        let err_flood = internal::on_ingress_frame_header(sess, ping_flood, 0);
        sub.assert_eq(err_flood, internal::ERR_ENHANCE_YOUR_CALM, "unacknowledged control frame flood triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-07: PING / SETTINGS with FLAG_ACK Do Not Increment Pending Counter") { sub =>
        var sess = internal::new_session_state();

        // Send 100 PING frames with FLAG_ACK (e.g. peer confirming our pings)
        var i: u32 = 0;
        while i < 100 {
            let ping_ack = internal::FrameHeader { length: 8, frame_type: internal::FRAME_PING, flags: internal::FLAG_ACK, stream_id: 0 };
            let err = internal::on_ingress_frame_header(sess, ping_ack, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "ping ack must be accepted without limit");
            i++;
        }
        sub.assert_eq(sess.pending_control_frames, 0, "pending_control_frames remains 0 for ACKs");

        // Send 100 SETTINGS frames with FLAG_ACK
        var j: u32 = 0;
        while j < 100 {
            let set_ack = internal::FrameHeader { length: 0, frame_type: internal::FRAME_SETTINGS, flags: internal::FLAG_ACK, stream_id: 0 };
            let err = internal::on_ingress_frame_header(sess, set_ack, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "settings ack must be accepted without limit");
            j++;
        }
        sub.assert_eq(sess.pending_control_frames, 0, "pending_control_frames remains 0 for SETTINGS ACKs");
    };

    t.run("DOS-08: Ingress Frame Size Check on HEADERS and CONTINUATION (RFC 9113 §4.2)") { sub =>
        var sess = internal::new_session_state();
        // local_max_frame_size = 16384 by default
        let big_headers = internal::FrameHeader { length: 20000, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        let err_h = internal::on_ingress_frame_header(sess, big_headers, 0);
        sub.assert_eq(err_h, internal::ERR_FRAME_SIZE_ERROR, "HEADERS frame exceeding max frame size rejected with FRAME_SIZE_ERROR");

        let big_cont = internal::FrameHeader { length: 20000, frame_type: internal::FRAME_CONTINUATION, flags: internal::FLAG_END_HEADERS, stream_id: 1 };
        let err_c = internal::on_ingress_frame_header(sess, big_cont, 0);
        sub.assert_eq(err_c, internal::ERR_FRAME_SIZE_ERROR, "CONTINUATION frame exceeding max frame size rejected with FRAME_SIZE_ERROR");
    };

    t.run("DOS-09: Stream Capacity 128 and Slot Reclamation on Full Close") { sub =>
        var sess = internal::new_session_state();
        sub.assert_eq(sess.streams.cap, 128, "streams storage capacity is 128");

        // Open 128 concurrent streams
        var sid: u32 = 1;
        while sid <= 255 {
            let h = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: sid };
            let err = internal::on_ingress_frame_header(sess, h, 0);
            sub.assert_eq(err, internal::ERR_NO_ERROR, "stream opened");
            sid += 2;
        }
        sub.assert_eq(sess.active_stream_count, 128, "all 128 streams active");

        // 129th stream rejected with REFUSED_STREAM
        let h_129 = internal::FrameHeader { length: 0, frame_type: internal::FRAME_HEADERS, flags: internal::FLAG_END_HEADERS, stream_id: 257 };
        let err_129 = internal::on_ingress_frame_header(sess, h_129, 0);
        sub.assert_eq(err_129, internal::ERR_REFUSED_STREAM, "129th stream refused due to max_concurrent_streams");

        // Close local side, then peer sends DATA with FLAG_END_STREAM
        internal::close_local_stream(sess, 1);
        let end_data = internal::FrameHeader { length: 0, frame_type: internal::FRAME_DATA, flags: internal::FLAG_END_STREAM, stream_id: 1 };
        let d_err = internal::on_data_frame_received(sess, end_data, 0);
        sub.assert_eq(d_err, internal::ERR_NO_ERROR, "data with end_stream processed");
        sub.assert_eq(sess.active_stream_count, 127, "active_stream_count decremented on full close");

        // Now stream 257 can be accepted in reclaimed slot
        let err_reopen = internal::on_ingress_frame_header(sess, h_129, 0);
        sub.assert_eq(err_reopen, internal::ERR_NO_ERROR, "slot reclaimed, new stream accepted");
        sub.assert_eq(sess.active_stream_count, 128, "active count restored to 128");
    };
}

// --- Component: http2_server ---
// tests/h2_server_test.goose
// Verification test suite for HTTP/2 Server Frame Multiplexer (RFC 9113 & RFC 7541).

// Helper to encode a client request HEADERS frame
fn encode_client_headers<B>(
    dt: internal::DynamicTable&,
    stream_id: u32,
    method: const u8[:],
    path: const u8[:],
    authority: const u8[:],
    end_stream: bool,
    out: B&,
) {
    var hdr_block: u8[>..] = [];
    internal::encode_hpack_field(dt, hdr_block, ":method", method, true, false);
    internal::encode_hpack_field(dt, hdr_block, ":path", path, true, false);
    internal::encode_hpack_field(dt, hdr_block, ":scheme", "https", true, false);
    internal::encode_hpack_field(dt, hdr_block, ":authority", authority, true, false);

    var flags: u8 = internal::FLAG_END_HEADERS;
    if end_stream {
        flags |= internal::FLAG_END_STREAM;
    }

    let hdr = internal::FrameHeader {
        length: hdr_block.len as u32,
        frame_type: internal::FRAME_HEADERS,
        flags: flags,
        stream_id: stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hdr_block[..]);
}

// Helper to encode a client DATA frame
fn encode_client_data<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) {
    let flags: u8 = if end_stream { internal::FLAG_END_STREAM } else { 0 };
    let hdr = internal::FrameHeader {
        length: payload.len as u32,
        frame_type: internal::FRAME_DATA,
        flags: flags,
        stream_id: stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(payload);
}

// Helper to encode client trailers in a HEADERS frame
fn encode_client_trailers<B>(
    dt: internal::DynamicTable&,
    stream_id: u32,
    name: const u8[:],
    value: const u8[:],
    out: B&,
) {
    var hdr_block: u8[>..] = [];
    internal::encode_hpack_field(dt, hdr_block, name, value, true, false);
    let hdr = internal::FrameHeader {
        length: hdr_block.len as u32,
        frame_type: internal::FRAME_HEADERS,
        flags: internal::FLAG_END_HEADERS | internal::FLAG_END_STREAM,
        stream_id: stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hdr_block[..]);
}

// 1. Connection Preface, Handshake & Settings Negotiation
fn test_h2_handshake_and_settings(t: core::T&) {
    t.run("H2-01: Preface & Initial Server SETTINGS emission") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var out_wire: u8[..512] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", internal::H2_CLIENT_PREFACE[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on preface");
        sub.assert_eq(consumed, 24, "Consumed 24 bytes of client preface");
        sub.assert_true(sess.preface_handled, "preface_handled flag is true");
        sub.assert_true(sess.server_settings_sent, "server_settings_sent flag is true");

        // Server must emit SETTINGS frame (type 0x04, length 24, stream 0)
        sub.assert_ge(out_wire.len, 9, "Output has frame header");
        let f_hdr, err_f = internal::parse_frame_header(out_wire[..9]);
        sub.assert_eq(err_f, internal::ERR_NO_ERROR, "Decoded frame header");
        sub.assert_eq(f_hdr.frame_type, internal::FRAME_SETTINGS, "Frame is SETTINGS");
        sub.assert_eq(f_hdr.stream_id, 0, "SETTINGS on stream 0");
        sub.assert_eq(f_hdr.length, 24, "SETTINGS payload is 24 bytes (4 settings)");
    };

    t.run("H2-02: Client SETTINGS ACK & PING ACK") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Prepend preface
        var wire: u8[..512] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Client SETTINGS (empty)
        let s_hdr = internal::FrameHeader {
            length: 0,
            frame_type: internal::FRAME_SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        internal::encode_frame_header_to(s_hdr, wire);

        // Client PING with 8-byte opaque data
        let p_hdr = internal::FrameHeader {
            length: 8,
            frame_type: internal::FRAME_PING,
            flags: 0,
            stream_id: 0,
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
        sub.assert_eq(f2_hdr.frame_type, internal::FRAME_SETTINGS, "Frame 2 is SETTINGS");
        sub.assert_true((f2_hdr.flags & internal::FLAG_ACK) != 0, "Frame 2 has FLAG_ACK");

        // Check Frame 3 (PING ACK)
        let f3_hdr, _ = internal::parse_frame_header(out_wire[42..51]);
        sub.assert_eq(f3_hdr.frame_type, internal::FRAME_PING, "Frame 3 is PING");
        sub.assert_true((f3_hdr.flags & internal::FLAG_ACK) != 0, "Frame 3 has FLAG_ACK");
        let ping_echo = out_wire[51..59];
        sub.assert_eq(ping_echo[0], 0x11, "PING opaque byte 0 matched");
        sub.assert_eq(ping_echo[7], 0x88, "PING opaque byte 7 matched");
    };

    t.run("H2-02b: Outbound Frame Aggregation with Zero-Heap CorkBuffer") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[..256] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        let p_hdr = internal::FrameHeader {
            length: 8,
            frame_type: internal::FRAME_PING,
            flags: 0,
            stream_id: 0,
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
        sub.assert_eq(f2_hdr.frame_type, internal::FRAME_PING, "Frame 2 is PING ACK in cork");
        sub.assert_true((f2_hdr.flags & internal::FLAG_ACK) != 0, "FLAG_ACK set on PING response");

        core::cork_consume(cork, 33);
        sub.assert_eq(cork.cork_pending(), 17, "Remaining 17 bytes after partial cork consume");
    };
}

// 2. Stream Multiplexing, Request Dispatching & HPACK Response Generation
fn test_h2_request_dispatch(t: core::T&) {
    t.run("H2-03: Single GET Request through Server Pipeline") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/api/greet", 101);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
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
        sub.assert_eq(err_rh, internal::ERR_NO_ERROR, "Decoded response frame header");
        sub.assert_eq(resp_hdr.frame_type, internal::FRAME_HEADERS, "Response frame is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
        sub.assert_true((resp_hdr.flags & internal::FLAG_END_HEADERS) != 0, "Response has END_HEADERS");

        // Decode response headers with client HPACK table
        var dec_resp = internal::DecodedH2HeaderList { .. };
        let hpack_payload = out_wire[42..42 + resp_hdr.length];
        let dec_err = internal::decode_hpack_header_block(client_hpack, hpack_payload, dec_resp);
        sub.assert_eq(dec_err, internal::ERR_NO_ERROR, "Client decoded response HPACK without error");

        // Verify :status == 200
        var found_status = false;
        var status_code_val: u8[..16] = [];
        for &f in dec_resp.fields {
            if f.name[..] == ":status" {
                found_status = true;
                status_code_val.clear();
                status_code_val.append(f.value[..]);
            }
        }
        sub.assert_true(found_status, "Found :status in response headers");
        sub.assert_bytes_eq(status_code_val[..], "200", ":status is 200");
    };

    t.run("H2-04: POST Request with DATA Frame Payload") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/api/data", 202);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/first", 1);
        wing::add_route(pipeline.router, "GET", "/second", 2);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..1024] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
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
            if err_f == internal::ERR_NO_ERROR && f_hdr.frame_type == internal::FRAME_HEADERS {
                if f_hdr.stream_id == 1 { found_stream_1 = true; }
                if f_hdr.stream_id == 3 { found_stream_3 = true; }
            }
            off += 9 + (f_hdr.length as i64);
        }

        sub.assert_true(found_stream_1, "Found response HEADERS on stream 1");
        sub.assert_true(found_stream_3, "Found response HEADERS on stream 3");
    };
}

// 3. End-to-End HttpServer Integration with HTTP/2 Preface Detection
fn test_h2_server_wire_integration(t: core::T&) {
    t.run("HttpServer.handle_connection_wire auto-detects H2 and serves requests") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/ping", 999);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire_in: u8[..512] = [];
        wire_in.append(internal::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/ping", "127.0.0.1", true, wire_in);

        var wire_out: u8[..1024] = [];
        let outcome, ok = wing::handle_connection_wire(server, "127.0.0.1", wire_in[..], 1700000000000000, wire_out);

        sub.assert_true(ok, "handle_connection_wire succeeded on HTTP/2 stream");
        sub.assert_true(outcome == wing::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_gt(wire_out.len, 33, "Generated HTTP/2 response frames");
        sub.assert_ge(server.requests_processed, 1, "Requests processed incremented");
    };
}

// 4. CONTINUATION Assembly, Anti-DoS & Rapid Reset Defense
fn test_h2_continuation_and_anti_dos(t: core::T&) {
    t.run("H2-06: Multi-Frame CONTINUATION Header Assembly") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/split/headers", 200);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);

        // Prepend preface
        var wire: u8[..1024] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Encode full header block
        var hdr_block: u8[..512] = [];
        internal::encode_hpack_field(client_hpack, hdr_block, ":method", "GET", true, false);
        internal::encode_hpack_field(client_hpack, hdr_block, ":path", "/split/headers", true, false);
        internal::encode_hpack_field(client_hpack, hdr_block, ":scheme", "https", true, false);
        internal::encode_hpack_field(client_hpack, hdr_block, ":authority", "localhost", true, false);

        sub.assert_gt(hdr_block.len, 10, "Header block non-empty");

        // Split header block into two frames:
        // Frame 1: HEADERS (first 10 bytes, flags: END_STREAM, NO END_HEADERS)
        let part1 = hdr_block[..10];
        let part2 = hdr_block[10..];

        let h_hdr = internal::FrameHeader {
            length: part1.len as u32,
            frame_type: internal::FRAME_HEADERS,
            flags: internal::FLAG_END_STREAM, // No FLAG_END_HEADERS!
            stream_id: 1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        wire.append(part1);

        // Frame 2: CONTINUATION (remaining bytes, flags: END_HEADERS)
        let c_hdr = internal::FrameHeader {
            length: part2.len as u32,
            frame_type: internal::FRAME_CONTINUATION,
            flags: internal::FLAG_END_HEADERS, // Terminal CONTINUATION frame
            stream_id: 1,
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
        sub.assert_eq(resp_hdr.frame_type, internal::FRAME_HEADERS, "Response is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
    };

    t.run("H2-07: Ban Zero-Length Non-Terminal CONTINUATION (CVE-2024-2758 / CVE-2024-31309)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[..512] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS without END_HEADERS
        let h_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_HEADERS,
            flags: 0,
            stream_id: 1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        // Frame 2: Zero-length non-terminal CONTINUATION frame (CVE-2024-2758 exploit attempt)
        let c_hdr = internal::FrameHeader {
            length: 0,
            frame_type: internal::FRAME_CONTINUATION,
            flags: 0, // No END_HEADERS!
            stream_id: 1,
        };
        internal::encode_frame_header_to(c_hdr, wire);

        var out_wire: u8[..512] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        // Must reject with GOAWAY PROTOCOL_ERROR
        sub.assert_false(ok, "Ingress rejected zero-length non-terminal CONTINUATION");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
    };

    t.run("H2-08: Rapid Reset Batch Bypass (CVE-2023-44487)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/fast/reset", 50);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS stream 1
        encode_client_headers(client_hpack, 1, "GET", "/fast/reset", "localhost", true, wire);

        // Frame 2: Immediate RST_STREAM stream 1 (Rapid Reset attack pattern)
        let rst_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_RST_STREAM,
            flags: 0,
            stream_id: 1,
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

// 5. RFC 9113 Protocol Invariants & Zero-Allocation Ingress
fn test_h2_protocol_invariants(t: core::T&) {
    t.run("H2-09: Client Request Trailers Accepted (RFC 9113 §8.1.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/upload/trailers", 10);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
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
            if err_f == internal::ERR_NO_ERROR && f_hdr.frame_type == internal::FRAME_HEADERS && f_hdr.stream_id == 1 {
                found_resp = true;
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_resp, "Response HEADERS frame emitted on stream 1");
    };

    t.run("H2-10: Client Trailers with Pseudo-Headers Rejected (RFC 9113 §8.1.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/upload/pseudo-trailer", 11);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/upload/pseudo-trailer", "localhost", false, wire);
        encode_client_trailers(client_hpack, 1, ":status", "200", wire);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress remained alive on stream error");
        sub.assert_gt(out_wire.len, 33, "Output generated");
        let rst_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, internal::FRAME_RST_STREAM, "Emitted RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 1, "RST_STREAM on stream 1");
    };

    t.run("H2-11: Large Flow Control Ingress Window Replenishment (RFC 9113 §6.9)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/bulk", 12);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 13);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 14);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", false, wire);

        let wu_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id: 1,
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
            if f_hdr.frame_type == internal::FRAME_RST_STREAM && f_hdr.stream_id == 1 {
                found_rst = true;
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_rst, "Server emitted RST_STREAM on stream 1");
    };

    t.run("H2-14: Client SETTINGS_ENABLE_PUSH > 1 rejected, 0 and 1 accepted (RFC 9113 §6.5.2)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire_ok: u8[>..] = [];
        wire_ok.append(internal::H2_CLIENT_PREFACE[..]);
        let s_hdr = internal::FrameHeader {
            length: 6,
            frame_type: internal::FRAME_SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        internal::encode_frame_header_to(s_hdr, wire_ok);
        core::append_u16_be(wire_ok, internal::SETTING_ENABLE_PUSH);
        core::append_u32_be(wire_ok, 1);

        var out_ok: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_ok[..], 1000, out_ok);
        sub.assert_true(ok1, "Server accepted client ENABLE_PUSH == 1");

        var wire: u8[>..] = [];
        internal::encode_frame_header_to(s_hdr, wire);
        core::append_u16_be(wire, internal::SETTING_ENABLE_PUSH);
        core::append_u32_be(wire, 2);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Server rejected client ENABLE_PUSH > 1");
        sub.assert_gt(out_wire.len, 0, "Emitted GOAWAY");
        let g_hdr, _ = internal::parse_frame_header(out_wire[0..9]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "GOAWAY emitted");
    };

    t.run("H2-15: gRPC Response Body Preserved Without Spurious OK (RFC 9113)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/not-found", "localhost", true, wire);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress handled request");
        var has_data = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = internal::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == internal::FRAME_DATA && f_hdr.stream_id == 1 {
                has_data = true;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_false(has_data, "No DATA frame emitted for non-200 empty response");
    };

    t.run("H2-16: PRIORITY Self-Dependency Rejection (RFC 9113 §5.3.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
        let prio_hdr = internal::FrameHeader {
            length: 5,
            frame_type: internal::FRAME_PRIORITY,
            flags: 0,
            stream_id: 3,
        };
        internal::encode_frame_header_to(prio_hdr, wire);
        let prio_payload: u8[5] = [0x00, 0x00, 0x00, 0x03, 0x10];
        for b in prio_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Connection remains open");
        sub.assert_gt(out_wire.len, 33, "Output contains frames");
        let rst_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, internal::FRAME_RST_STREAM, "Frame is RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 3, "RST_STREAM on stream 3");
    };

    t.run("H2-17: HEADERS on Closed Stream Triggers RST_STREAM(STREAM_CLOSED) Not GOAWAY (RFC 9113 §5.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 17);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
        // Complete stream 1
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", true, wire);

        var out_wire: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);
        sub.assert_true(ok1, "Stream 1 completed normally");

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
            if f_hdr.frame_type == internal::FRAME_RST_STREAM && f_hdr.stream_id == 1 {
                found_rst = true;
                let code_r = core::new_slice_reader(out_wire2[off + 9..off + 13]);
                let err_code, _ = code_r.read_u32_be();
                sub.assert_eq(err_code, internal::ERR_STREAM_CLOSED, "RST_STREAM error code is STREAM_CLOSED");
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS stream 1 WITHOUT FLAG_END_HEADERS
        let h_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_HEADERS,
            flags: 0, // No END_HEADERS!
            stream_id: 1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        // Frame 2: Interleaved PING frame before END_HEADERS
        let ping_hdr = internal::FrameHeader {
            length: 8,
            frame_type: internal::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        internal::encode_frame_header_to(ping_hdr, wire);
        let ping_opaque: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        for b in ping_opaque { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected interleaved frame before END_HEADERS");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-19: Unprompted CONTINUATION Frame Triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.10)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Unprompted CONTINUATION frame without preceding HEADERS
        let c_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_CONTINUATION,
            flags: internal::FLAG_END_HEADERS,
            stream_id: 1,
        };
        internal::encode_frame_header_to(c_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected unprompted CONTINUATION");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-20: Client PUSH_PROMISE Frame Rejected with GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.6)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Client sends PUSH_PROMISE (promised stream id = 2, dummy header fragment)
        let pp_hdr = internal::FrameHeader {
            length: 5,
            frame_type: internal::FRAME_PUSH_PROMISE,
            flags: internal::FLAG_END_HEADERS,
            stream_id: 1,
        };
        internal::encode_frame_header_to(pp_hdr, wire);
        let pp_payload: u8[5] = [0x00, 0x00, 0x00, 0x02, 0x82];
        for b in pp_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Server rejected client PUSH_PROMISE");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-21: Duplicate / Unsolicited SETTINGS ACK Rejected with GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.5 & §10.5)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Frame 1: Valid SETTINGS ACK for server initial settings
        let ack_hdr1 = internal::FrameHeader {
            length: 0,
            frame_type: internal::FRAME_SETTINGS,
            flags: internal::FLAG_ACK,
            stream_id: 0,
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
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire2[13..17]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-22: Control Frame Flood (Excess PINGs/ACKs > 64) Triggers GOAWAY(ENHANCE_YOUR_CALM) (RFC 9113 §10.5)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Send 65 PING frames in a single batch (exceeding MAX_PENDING_CTRL_FRAMES = 64)
        for i in 65 {
            let ping_hdr = internal::FrameHeader {
                length: 8,
                frame_type: internal::FRAME_PING,
                flags: 0,
                stream_id: 0,
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
            if f_hdr.frame_type == internal::FRAME_GOAWAY {
                let g_r = core::new_slice_reader(out_wire[off + 13..off + 17]);
                let err_code, _ = g_r.read_u32_be();
                if err_code == internal::ERR_ENHANCE_YOUR_CALM {
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        let h_hdr = internal::FrameHeader {
            length: 2,
            frame_type: internal::FRAME_HEADERS,
            flags: internal::FLAG_END_HEADERS | internal::FLAG_END_STREAM,
            stream_id: 1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        wire.push(0x82); // Indexed header: :method: GET (sets updates_allowed = false)
        wire.push(0x20); // Dynamic Table Size Update: size 0 (ILLEGAL after regular header field)

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected mid-block dynamic table size update");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_COMPRESSION_ERROR, "GOAWAY code is COMPRESSION_ERROR");
    };

    t.run("H2-24: HPACK Out-of-Bounds Dynamic Table Index Lookup Rejected with COMPRESSION_ERROR (RFC 7541 §2.3.3)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        let h_hdr = internal::FrameHeader {
            length: 1,
            frame_type: internal::FRAME_HEADERS,
            flags: internal::FLAG_END_HEADERS | internal::FLAG_END_STREAM,
            stream_id: 1,
        };
        internal::encode_frame_header_to(h_hdr, wire);
        wire.push(0xBE); // 0x80 | 62: Indexed header lookup for index 62 when dynamic table is empty

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected out-of-bounds dynamic table index lookup");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_COMPRESSION_ERROR, "GOAWAY code is COMPRESSION_ERROR");
    };

    t.run("H2-25: PRIORITY_UPDATE on Stream 0 and Server-Initiated Stream Rejection (RFC 9218 §7.1)") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Sub-test A: Prioritized Stream ID 0 must be rejected with PROTOCOL_ERROR
        var wireA: u8[>..] = [];
        wireA.append(internal::H2_CLIENT_PREFACE[..]);
        let pu_hdrA = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_PRIORITY_UPDATE,
            flags: 0,
            stream_id: 0,
        };
        internal::encode_frame_header_to(pu_hdrA, wireA);
        let zeros: u8[4] = [0, 0, 0, 0]; // Prioritized stream 0
        for b in zeros { wireA.push(b); }

        var out_wireA: u8[>..] = [];
        let _, okA = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wireA[..], 1000, out_wireA);
        sub.assert_false(okA, "PRIORITY_UPDATE identifying stream 0 rejected");
        let g_rA = core::new_slice_reader(out_wireA[46..50]);
        let err_codeA, _ = g_rA.read_u32_be();
        sub.assert_eq(err_codeA, internal::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");

        // Sub-test B: Prioritized Stream ID 2 (server-initiated / even) must be rejected with PROTOCOL_ERROR
        var sessB = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wireB: u8[>..] = [];
        wireB.append(internal::H2_CLIENT_PREFACE[..]);
        let pu_hdrB = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_PRIORITY_UPDATE,
            flags: 0,
            stream_id: 0,
        };
        internal::encode_frame_header_to(pu_hdrB, wireB);
        let stream2: u8[4] = [0, 0, 0, 2]; // Even stream ID
        for b in stream2 { wireB.push(b); }

        var out_wireB: u8[>..] = [];
        let _, okB = internal::handle_h2_server_ingress(sessB, pipeline, timer, "127.0.0.1", wireB[..], 1000, out_wireB);
        sub.assert_false(okB, "PRIORITY_UPDATE identifying server-initiated stream rejected");
        let g_rB = core::new_slice_reader(out_wireB[46..50]);
        let err_codeB, _ = g_rB.read_u32_be();
        sub.assert_eq(err_codeB, internal::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");

        // Sub-test C: Valid PRIORITY_UPDATE for stream 1 applies priority update
        var sessC = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wireC: u8[>..] = [];
        wireC.append(internal::H2_CLIENT_PREFACE[..]);
        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", false, wireC);

        let pu_val: const u8[:] = "u=0, i";
        let pu_hdrC = internal::FrameHeader {
            length: (4 + pu_val.len) as u32,
            frame_type: internal::FRAME_PRIORITY_UPDATE,
            flags: 0,
            stream_id: 0,
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/fast/reset", 50);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Send 25 pairs of HEADERS + RST_STREAM in a single batch (exceeding old 16-element limit)
        for i in 25 {
            let s_id: u32 = ((i * 2) + 1) as u32;
            encode_client_headers(client_hpack, s_id, "GET", "/fast/reset", "localhost", true, wire);
            let rst_hdr = internal::FrameHeader {
                length: 4,
                frame_type: internal::FRAME_RST_STREAM,
                flags: 0,
                stream_id: s_id,
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 27);

        var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", true, wire);

        var out_wire1: u8[>..] = [];
        let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire1);
        sub.assert_true(ok1, "Stream 1 completed normally");

        // Now stream 1 is closed. Send WINDOW_UPDATE on stream 1
        var wire2: u8[>..] = [];
        let wu_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id: 1,
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
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

        // Connection send window starts at 65535.
        // Send WINDOW_UPDATE on stream 0 with increment 0x7FFFFFFF (2^31 - 1)
        // 65535 + 2147483647 exceeds 2^31 - 1 -> FLOW_CONTROL_ERROR
        let wu_hdr = internal::FrameHeader {
            length: 4,
            frame_type: internal::FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id: 0,
        };
        internal::encode_frame_header_to(wu_hdr, wire);
        core::append_u32_be(wire, 0x7FFFFFFF);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Window overflow rejected");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = internal::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, internal::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, internal::ERR_FLOW_CONTROL_ERROR, "GOAWAY code is FLOW_CONTROL_ERROR");
    };
}

// --- Component: http2_security ---
// Tests for HTTP/2 framer validation and frame limits (RFC 9113).

fn test_continuation_flood_and_interleaving(t: core::T&) {
    t.run("H2-01: CONTINUATION Flood Exceeding Frame Cap Rejection (CVE-2024-27983)") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        // 1. Initial HEADERS frame on stream 1 without END_HEADERS
        let h_hdr = internal::H2FrameHeader {
            payload_len: 100,
            frame_type: internal::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0, // No END_HEADERS
            stream_id: 1,
            valid: true,
        };
        let err0 = internal::process_incoming_frame(framer, h_hdr);
        sub.assert_eq(err0, internal::H2ErrorCode.NoError);
        sub.assert_true(framer.state == internal::H2ConnState.ExpectContinuation);

        // 2. Stream 5 valid CONTINUATION frames (allowed)
        for _ in 5 {
            let cont_hdr = internal::H2FrameHeader {
                payload_len: 100,
                frame_type: internal::H2FrameType.Continuation,
                raw_type: 0x9,
                flags: 0x0, // Not finished yet
                stream_id: 1,
                valid: true,
            };
            let err_cont = internal::process_incoming_frame(framer, cont_hdr);
            sub.assert_eq(err_cont, internal::H2ErrorCode.NoError);
        }

        // 3. 6th CONTINUATION frame (exceeds max_continuation_frames = 5) -> EnhanceYourCalm (DDoS mitigation)
        let flood_hdr = internal::H2FrameHeader {
            payload_len: 100,
            frame_type: internal::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let err_flood = internal::process_incoming_frame(framer, flood_hdr);
        sub.assert_eq(err_flood, internal::H2ErrorCode.EnhanceYourCalm, "CONTINUATION flood must be rejected with EnhanceYourCalm");
        sub.assert_true(framer.state == internal::H2ConnState.Closed);
    };

    t.run("H2-02: Stream Interleaving While Expecting CONTINUATION Rejection (RFC 9113 Section 4.3)") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        // HEADERS on stream 1 without END_HEADERS
        let h_hdr = internal::H2FrameHeader {
            payload_len: 50,
            frame_type: internal::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        internal::process_incoming_frame(framer, h_hdr);

        // Interleaved DATA frame on stream 1 (Illegal while expecting CONTINUATION)
        let data_hdr = internal::H2FrameHeader {
            payload_len: 10,
            frame_type: internal::H2FrameType.Data,
            raw_type: 0x0,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let err1 = internal::process_incoming_frame(framer, data_hdr);
        sub.assert_eq(err1, internal::H2ErrorCode.ProtocolError, "Non-CONTINUATION frame interleaved must trigger ProtocolError");

        // Reset and test interleaved CONTINUATION on DIFFERENT stream (stream 3 instead of 1)
        var framer2 = internal::H2SecurityFramer { .. };
        internal::process_incoming_frame(framer2, h_hdr);

        let cont_other_stream = internal::H2FrameHeader {
            payload_len: 50,
            frame_type: internal::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x0,
            stream_id: 3, // Different stream!
            valid: true,
        };
        let err2 = internal::process_incoming_frame(framer2, cont_other_stream);
        sub.assert_eq(err2, internal::H2ErrorCode.ProtocolError, "CONTINUATION on different stream must trigger ProtocolError");
    };

    t.run("H2-03: Cumulative Header Block Size Bomb Rejection") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        // HEADERS with 4000 bytes
        let h_hdr = internal::H2FrameHeader {
            payload_len: 4000,
            frame_type: internal::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        internal::process_incoming_frame(framer, h_hdr);

        // CONTINUATION with 5000 bytes (total 9000 > max_header_block_bytes 8192)
        let cont_bomb = internal::H2FrameHeader {
            payload_len: 5000,
            frame_type: internal::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x4, // END_HEADERS
            stream_id: 1,
            valid: true,
        };
        let err = internal::process_incoming_frame(framer, cont_bomb);
        sub.assert_eq(err, internal::H2ErrorCode.EnhanceYourCalm, "Cumulative header block > 8KB must be rejected with EnhanceYourCalm");
    };

    t.run("H2-04: Valid CONTINUATION Sequence with END_HEADERS") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        let h_hdr = internal::H2FrameHeader {
            payload_len: 200,
            frame_type: internal::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        sub.assert_eq(internal::process_incoming_frame(framer, h_hdr), internal::H2ErrorCode.NoError);

        let cont_final = internal::H2FrameHeader {
            payload_len: 300,
            frame_type: internal::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: internal::H2_FLAG_END_HEADERS,
            stream_id: 1,
            valid: true,
        };
        sub.assert_eq(internal::process_incoming_frame(framer, cont_final), internal::H2ErrorCode.NoError);
        sub.assert_true(framer.state == internal::H2ConnState.Idle, "State returned to Idle on END_HEADERS");
    };
}

fn test_rapid_reset_and_dos_floods(t: core::T&) {
    t.run("RESET-01: Rapid Reset Flood Defense (CVE-2023-44487)") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        // 100 RST_STREAM frames processed (under limit)
        for _ in 100 {
            let rst = internal::H2FrameHeader {
                payload_len: 4,
                frame_type: internal::H2FrameType.RstStream,
                raw_type: 0x3,
                flags: 0x0,
                stream_id: 1,
                valid: true,
            };
            let err = internal::process_incoming_frame(framer, rst);
            sub.assert_eq(err, internal::H2ErrorCode.NoError);
        }

        // 101st RST_STREAM frame (exceeds max_rapid_resets = 100) -> EnhanceYourCalm
        let rst_flood = internal::H2FrameHeader {
            payload_len: 4,
            frame_type: internal::H2FrameType.RstStream,
            raw_type: 0x3,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let err_flood = internal::process_incoming_frame(framer, rst_flood);
        sub.assert_eq(err_flood, internal::H2ErrorCode.EnhanceYourCalm, "Rapid reset flood must trigger EnhanceYourCalm");
        sub.assert_true(framer.state == internal::H2ConnState.Closed);
    };

    t.run("PING-01: PING Flood Defense (CVE-2019-9512)") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        // 10 unacknowledged PING frames allowed
        for _ in 10 {
            let ping = internal::H2FrameHeader {
                payload_len: 8,
                frame_type: internal::H2FrameType.Ping,
                raw_type: 0x6,
                flags: 0x0, // Not an ACK
                stream_id: 0,
                valid: true,
            };
            sub.assert_eq(internal::process_incoming_frame(framer, ping), internal::H2ErrorCode.NoError);
        }

        // 11th unacknowledged PING -> EnhanceYourCalm
        let ping_flood = internal::H2FrameHeader {
            payload_len: 8,
            frame_type: internal::H2FrameType.Ping,
            raw_type: 0x6,
            flags: 0x0,
            stream_id: 0,
            valid: true,
        };
        sub.assert_eq(internal::process_incoming_frame(framer, ping_flood), internal::H2ErrorCode.EnhanceYourCalm);
    };
}

fn test_settings_and_stream_id_invariants(t: core::T&) {
    t.run("SETTING-01: SETTINGS_MAX_FRAME_SIZE=0 Infinite Loop Defense ") { sub =>
        // Setting 0 must trigger ProtocolError
        let err0 = internal::validate_h2_setting(0x5, 0);
        sub.assert_eq(err0, internal::H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE=0 must return ProtocolError");

        // Setting < 16,384 must trigger ProtocolError
        let err1 = internal::validate_h2_setting(0x5, 1000);
        sub.assert_eq(err1, internal::H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE < 16384 must return ProtocolError");

        // Min valid: 16,384
        let err_min = internal::validate_h2_setting(0x5, 16384);
        sub.assert_eq(err_min, internal::H2ErrorCode.NoError, "SETTINGS_MAX_FRAME_SIZE=16384 is valid");

        // Max valid: 16,777,215 (2^24 - 1)
        let err_max = internal::validate_h2_setting(0x5, 16777215);
        sub.assert_eq(err_max, internal::H2ErrorCode.NoError, "SETTINGS_MAX_FRAME_SIZE=16777215 is valid");

        // Setting > 16,777,215 must trigger ProtocolError
        let err_ovf = internal::validate_h2_setting(0x5, 20000000);
        sub.assert_eq(err_ovf, internal::H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE > 16777215 must return ProtocolError");
    };

    t.run("STREAM-01: Stream ID Parity & Connection-Level Isolation (RFC 9113 Section 5.1.1)") { sub =>
        var framer = internal::H2SecurityFramer { .. };

        // 1. Client HEADERS on even stream (stream 2) -> ProtocolError
        let even_hdr = internal::H2FrameHeader {
            payload_len: 20,
            frame_type: internal::H2FrameType.Headers,
            raw_type: 0x1,
            flags: internal::H2_FLAG_END_HEADERS,
            stream_id: 2, // Even stream
            valid: true,
        };
        sub.assert_eq(internal::process_incoming_frame(framer, even_hdr), internal::H2ErrorCode.ProtocolError, "Client HEADERS on even stream must fail");

        // 2. Client HEADERS on stream 0 -> ProtocolError
        let stream0_hdr = internal::H2FrameHeader {
            payload_len: 20,
            frame_type: internal::H2FrameType.Headers,
            raw_type: 0x1,
            flags: internal::H2_FLAG_END_HEADERS,
            stream_id: 0,
            valid: true,
        };
        sub.assert_eq(internal::process_incoming_frame(framer, stream0_hdr), internal::H2ErrorCode.ProtocolError, "HEADERS on stream 0 must fail");

        // 3. SETTINGS on stream > 0 -> ProtocolError
        let s_hdr = internal::H2FrameHeader {
            payload_len: 6,
            frame_type: internal::H2FrameType.Settings,
            raw_type: 0x4,
            flags: 0x0,
            stream_id: 1, // Must be stream 0!
            valid: true,
        };
        sub.assert_eq(internal::process_incoming_frame(framer, s_hdr), internal::H2ErrorCode.ProtocolError, "SETTINGS on stream 1 must fail");
    };
}

fn test_h2_wire_framing_and_types(t: core::T&) {
    t.run("WIRE-01: Frame Type Mapping and Extension Handling (RFC 9113 Sec 6)") { sub =>
        sub.assert_eq(internal::byte_to_frame_type(0x0), internal::H2FrameType.Data, "0x0 is Data");
        sub.assert_eq(internal::byte_to_frame_type(0x1), internal::H2FrameType.Headers, "0x1 is Headers");
        sub.assert_eq(internal::byte_to_frame_type(0x2), internal::H2FrameType.Priority, "0x2 is Priority");
        sub.assert_eq(internal::byte_to_frame_type(0x3), internal::H2FrameType.RstStream, "0x3 is RstStream");
        sub.assert_eq(internal::byte_to_frame_type(0x4), internal::H2FrameType.Settings, "0x4 is Settings");
        sub.assert_eq(internal::byte_to_frame_type(0x5), internal::H2FrameType.PushPromise, "0x5 is PushPromise");
        sub.assert_eq(internal::byte_to_frame_type(0x6), internal::H2FrameType.Ping, "0x6 is Ping");
        sub.assert_eq(internal::byte_to_frame_type(0x7), internal::H2FrameType.GoAway, "0x7 is GoAway");
        sub.assert_eq(internal::byte_to_frame_type(0x8), internal::H2FrameType.WindowUpdate, "0x8 is WindowUpdate");
        sub.assert_eq(internal::byte_to_frame_type(0x9), internal::H2FrameType.Continuation, "0x9 is Continuation");
        sub.assert_eq(internal::byte_to_frame_type(0x0A), internal::H2FrameType.Unknown, "0x0A is Unknown");
        sub.assert_eq(internal::byte_to_frame_type(0xFF), internal::H2FrameType.Unknown, "0xFF is Unknown");
    };

    t.run("WIRE-02: 9-Byte Frame Header Decoding & Reserved Bit Masking (RFC 9113 Sec 4.1)") { sub =>
        // Truncated header (< 9 bytes)
        var short_buf: u8[8] = [0; 8];
        let _, err_short = internal::parse_h2_frame_header(short_buf[..]);
        sub.assert_eq(err_short, internal::H2ErrorCode.FrameSizeError, "short header returns FrameSizeError");

        // Valid DATA frame: length 128 (0x000080), type 0x00, flags 0x01 (END_STREAM), stream 5 (0x00000005)
        var data_hdr_raw: u8[9] = [
            0x00, 0x00, 0x80, // length = 128
            0x00,             // type = DATA
            0x01,             // flags = END_STREAM
            0x00, 0x00, 0x00, 0x05, // stream ID = 5
        ];
        let h1, err1 = internal::parse_h2_frame_header(data_hdr_raw[..]);
        sub.assert_eq(err1, internal::H2ErrorCode.NoError, "valid DATA header returns NoError");
        sub.assert_true(h1.valid, "valid flag is true");
        sub.assert_eq(h1.payload_len, 128, "payload len is 128");
        sub.assert_eq(h1.frame_type, internal::H2FrameType.Data, "frame type is Data");
        sub.assert_eq(h1.flags, 0x01, "flags match");
        sub.assert_eq(h1.stream_id, 5, "stream id is 5");

        // HEADERS frame with reserved high bit set: stream 0x80000003 -> masked to 3
        var res_hdr_raw: u8[9] = [
            0x00, 0x01, 0x00, // length = 256
            0x01,             // type = HEADERS
            0x04,             // flags = END_HEADERS
            0x80, 0x00, 0x00, 0x03, // stream ID = 3 with high bit set
        ];
        let h2, err2 = internal::parse_h2_frame_header(res_hdr_raw[..]);
        sub.assert_eq(err2, internal::H2ErrorCode.NoError, "reserved bit header returns NoError");
        sub.assert_eq(h2.stream_id, 3, "reserved bit masked out to stream id 3");
        sub.assert_eq(h2.payload_len, 256, "payload len is 256");
    };
}

// --- Component: http2_fsm_continuation ---
// Hardening & Security Invariants Suite for HTTP/2 Connection State Machine (RFC 9113):
// 1. SETTINGS & PING frame invariants (length % 6 == 0, ACK length == 0, Stream 0 binding).
// 2. Flow control window arithmetic, 31-bit overflow guards, and zero-increment bans.
// 3. CONTINUATION flood defense (CVE-2024-27983) and illegal frame interleaving bans.

fn test_h2_settings_and_ping_invariants(t: core::T&) {
    t.run("H2-SEC-01: SETTINGS ACK with Non-Zero Length must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr = internal::FrameHeader {
            length: 6, // Length != 0 with ACK is illegal per RFC 9113 §6.5
            frame_type: internal::FRAME_SETTINGS,
            flags: internal::FLAG_ACK,
            stream_id: 0,
        };
        let err = internal::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, internal::ERR_FRAME_SIZE_ERROR, "SETTINGS with ACK and length > 0 must trigger FRAME_SIZE_ERROR");
    };

    t.run("H2-SEC-02: SETTINGS with Length not multiple of 6 must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr = internal::FrameHeader {
            length: 5, // Not multiple of 6
            frame_type: internal::FRAME_SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        let err = internal::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, internal::ERR_FRAME_SIZE_ERROR, "SETTINGS length not multiple of 6 must trigger FRAME_SIZE_ERROR");
    };

    t.run("H2-SEC-03: SETTINGS or PING on Stream != 0 must trigger PROTOCOL_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);

        // SETTINGS on stream 1
        let hdr_set = internal::FrameHeader {
            length: 6,
            frame_type: internal::FRAME_SETTINGS,
            flags: 0,
            stream_id: 1, // Illegal: MUST be stream 0 per RFC 9113 §6.5
        };
        let err_set = internal::on_ingress_frame_header(conn, hdr_set, 0);
        sub.assert_eq(err_set, internal::ERR_PROTOCOL_ERROR, "SETTINGS on stream != 0 must trigger PROTOCOL_ERROR");

        // PING on stream 1
        let hdr_ping = internal::FrameHeader {
            length: 8,
            frame_type: internal::FRAME_PING,
            flags: 0,
            stream_id: 1, // Illegal: MUST be stream 0 per RFC 9113 §6.7
        };
        let err_ping = internal::on_ingress_frame_header(conn, hdr_ping, 0);
        sub.assert_eq(err_ping, internal::ERR_PROTOCOL_ERROR, "PING on stream != 0 must trigger PROTOCOL_ERROR");
    };

    t.run("H2-SEC-04: PING with Length != 8 must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr = internal::FrameHeader {
            length: 7, // Illegal: MUST be exactly 8 per RFC 9113 §6.7
            frame_type: internal::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        let err = internal::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, internal::ERR_FRAME_SIZE_ERROR, "PING with length != 8 must trigger FRAME_SIZE_ERROR");
    };
}

fn test_h2_window_update_and_flow_control(t: core::T&) {
    t.run("H2-SEC-05: WINDOW_UPDATE Increment 0 is Forbidden (RFC 9113 §6.9)") { sub =>
        var conn = internal::new_h2_connection(0);
        let err_conn = internal::apply_window_update(conn, 0, 0);
        sub.assert_eq(err_conn, internal::ERR_PROTOCOL_ERROR, "WINDOW_UPDATE with increment 0 on connection must trigger PROTOCOL_ERROR");

        let err_str = internal::apply_window_update(conn, 1, 0);
        sub.assert_eq(err_str, internal::ERR_PROTOCOL_ERROR, "WINDOW_UPDATE with increment 0 on stream must trigger PROTOCOL_ERROR");
    };

    t.run("H2-SEC-06: Connection Window Overflow beyond 2^31 - 1 triggers FLOW_CONTROL_ERROR") { sub =>
        var conn = internal::new_h2_connection(0);
        // Default conn_send_window is 65535
        // Adding 0x7FFFFFFF will overflow MAX_INITIAL_WINDOW_SIZE (0x7FFFFFFF)
        let err = internal::apply_window_update(conn, 0, 0x7FFFFFFF);
        sub.assert_eq(err, internal::ERR_FLOW_CONTROL_ERROR, "Connection window overflow must trigger FLOW_CONTROL_ERROR");
    };

    t.run("H2-SEC-07: Excessive Initial Window Updates Flood Defense (CVE-2026-78669)") { sub =>
        var conn = internal::new_h2_connection(0);
        var hit_flood = false;
        for _ in 20 {
            let err = internal::apply_peer_initial_window_size_delta(conn, 65535);
            if err == internal::ERR_ENHANCE_YOUR_CALM {
                hit_flood = true;
                break;
            }
        }
        sub.assert_true(hit_flood, "Repeated initial window size delta flood must trigger ENHANCE_YOUR_CALM");
    };
}

fn test_h2_continuation_flood_and_interleaving(t: core::T&) {
    t.run("H2-SEC-08: Interleaved Frame During Continuation Sequence Forbidden (RFC 9113 §4.3)") { sub =>
        var conn = internal::new_h2_connection(0);

        // 1. Initial HEADERS frame on stream 1 without END_HEADERS flag
        let h_hdr = internal::FrameHeader {
            length: 100,
            frame_type: internal::FRAME_HEADERS,
            flags: 0, // FLAG_END_HEADERS not set
            stream_id: 1,
        };
        let err_h = internal::on_ingress_frame_header(conn, h_hdr, 0);
        sub.assert_eq(err_h, internal::ERR_NO_ERROR, "HEADERS frame enters continuation state cleanly");
        sub.assert_eq(conn.continuation_stream_id, 1, "connection expects continuation on stream 1");

        // 2. Interleaved PING frame on stream 0 arrives before CONTINUATION
        let ping_hdr = internal::FrameHeader {
            length: 8,
            frame_type: internal::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        let err_ping = internal::on_ingress_frame_header(conn, ping_hdr, 0);
        sub.assert_eq(err_ping, internal::ERR_PROTOCOL_ERROR, "Interleaved PING during continuation sequence must trigger PROTOCOL_ERROR per RFC 9113 §4.3");

        // 3. Interleaved DATA on stream 1 arrives before CONTINUATION
        let data_hdr = internal::FrameHeader {
            length: 50,
            frame_type: internal::FRAME_DATA,
            flags: 0,
            stream_id: 1,
        };
        let err_data = internal::on_ingress_frame_header(conn, data_hdr, 0);
        sub.assert_eq(err_data, internal::ERR_PROTOCOL_ERROR, "Interleaved DATA during continuation sequence must trigger PROTOCOL_ERROR per RFC 9113 §4.3");
    };

    t.run("H2-SEC-09: CONTINUATION on Different Stream ID Rejected (RFC 9113 §6.10)") { sub =>
        var conn = internal::new_h2_connection(0);

        // HEADERS on stream 3 without END_HEADERS
        let h_hdr = internal::FrameHeader {
            length: 50,
            frame_type: internal::FRAME_HEADERS,
            flags: 0,
            stream_id: 3,
        };
        let _ = internal::on_ingress_frame_header(conn, h_hdr, 0);

        // CONTINUATION arrives on stream 5 instead of 3
        let cont_hdr = internal::FrameHeader {
            length: 50,
            frame_type: internal::FRAME_CONTINUATION,
            flags: 0,
            stream_id: 5,
        };
        let err_cont = internal::on_ingress_frame_header(conn, cont_hdr, 0);
        sub.assert_eq(err_cont, internal::ERR_PROTOCOL_ERROR, "CONTINUATION on different stream ID must trigger PROTOCOL_ERROR per RFC 9113 §6.10");
    };
}

// --- Component: http2_hpack_invariants ---
// Hardening & Security Invariants Suite for HPACK / RFC 7541 and RFC 9113:
// 1. Shift overflow & 31-bit integer boundary attacks (FIND-401).
// 2. Dynamic table LIFO index mapping, eviction to 0, and ring buffer wrap-around.
// 3. Dynamic table size update placement & bounds enforcement.
// 4. RFC 9113 pseudo-header ordering, duplicate checks, and connection header bans.

fn test_hpack_integer_codec_overflows(t: core::T&) {
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

fn test_hpack_dynamic_table_invariants(t: core::T&) {
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

fn test_hpack_rfc9113_header_block_rules(t: core::T&) {
    t.run("HPACK-SEC-08: Dynamic Table Size Update in middle of Block Rejected") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var out_list = internal::DecodedH2HeaderList { .. };

        // Header block:
        // 1. Static index 2 (:method: GET) -> 0x82
        // 2. Dynamic table size update: 001xxxxx -> 0x3F 0x00 (size = 31)
        let bad_block: u8[3] = [0x82, 0x3F, 0x00];
        let err = internal::decode_hpack_header_block(dt, bad_block[..], out_list);
        sub.assert_eq(err, internal::ERR_COMPRESSION_ERROR, "table size update after regular header must fail with COMPRESSION_ERROR per RFC 7541 §4.2");
    };

    t.run("HPACK-SEC-09: Table Size Update Exceeding SETTINGS Max Rejected") { sub =>
        var dt = internal::new_dynamic_table(1024); // max allowed size = 1024
        var out_list = internal::DecodedH2HeaderList { .. };

        // Table size update requesting 2048:
        // 001xxxxx prefix 5: 0x3F (31), followed by (2048 - 31) = 2017 -> 2017 = 0x7E1 -> 0xE1 0x0F
        let oversize_block: u8[3] = [0x3F, 0xE1, 0x0F];
        let err = internal::decode_hpack_header_block(dt, oversize_block[..], out_list);
        sub.assert_eq(err, internal::ERR_COMPRESSION_ERROR, "size update exceeding max_allowed_size must trigger COMPRESSION_ERROR");
    };

    t.run("HPACK-SEC-10: Pseudo-Header Ordering (Pseudo After Regular Rejected)") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var out_list = internal::DecodedH2HeaderList { .. };

        // Header block:
        // 1. Static index 24 (cache-control: no-cache) -> 0x98 (regular header)
        // 2. Static index 2 (:method: GET) -> 0x82 (pseudo-header)
        let out_of_order_block: u8[2] = [0x98, 0x82];
        let err = internal::decode_hpack_header_block(dt, out_of_order_block[..], out_list);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "pseudo-header after regular header must trigger PROTOCOL_ERROR per RFC 9113 §8.3");
    };

    t.run("HPACK-SEC-11: Forbidden Connection Headers in HTTP/2 Rejected") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var out_list = internal::DecodedH2HeaderList { .. };

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

        let err = internal::decode_hpack_header_block(dt, conn_block[..], out_list);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "Connection header must trigger PROTOCOL_ERROR per RFC 9113 §8.2.2");
    };

    t.run("HPACK-SEC-12: Disallowed TE Header Value Rejected") { sub =>
        var dt = internal::new_dynamic_table(4096);
        var out_list = internal::DecodedH2HeaderList { .. };

        // TE header with value other than "trailers" (e.g. "gzip") is illegal in HTTP/2
        var te_block: u8[..64] = [];
        te_block.push(0x82); // :method: GET
        te_block.push(0x40); // Literal with indexing
        te_block.push(2);    // "te"
        te_block.append("te");
        te_block.push(4);    // "gzip"
        te_block.append("gzip");

        let err = internal::decode_hpack_header_block(dt, te_block[..], out_list);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "TE header with value other than 'trailers' must trigger PROTOCOL_ERROR per RFC 9113 §8.2.2");
    };
}

// --- Component: http2_extended_connect ---
// Verification suite for RFC 8441 & RFC 9220: Extended CONNECT (WebSockets over H2 and H3):
// - Detection of Extended CONNECT vs classic TCP tunnel CONNECT
// - HTTP/3 client request formatting (:protocol = websocket)
// - Strict protocol invariance: rejection of Upgrade/Connection/Sec-WebSocket-Key
// - Server-side upgrade producing 200 OK and subprotocol negotiation
// - Zero-allocation stream encapsulation of masked (client) and unmasked (server) WS frames

fn test_extended_connect_detection(t: core::T&) {
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

fn test_h3_websocket_formatting(t: core::T&) {
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

fn test_h3_server_upgrade(t: core::T&) {
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

fn test_stream_frame_encapsulation(t: core::T&) {
    t.run("Stream Encapsulation of Masked and Unmasked Frames") { sub =>
        // 1. Client frame (MUST be masked)
        var client_data: u8[>..] = [];
        let mask: const u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        wing::ws_encapsulate_stream_data(client_data, wing::WS_OPCODE_TEXT, "Hello H3 WebSocket", true, mask);

        let hdr_c, ok_c = wing::parse_ws_frame_header(client_data[..]);
        sub.assert_true(ok_c, "Client frame header parsed");
        sub.assert_true(hdr_c.masked, "Client frame has mask bit set");
        sub.assert_eq(hdr_c.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");

        // 2. Server frame (MUST NOT be masked per RFC 6455 §5.1 / RFC 8441 / RFC 9220)
        var server_data: u8[>..] = [];
        wing::ws_encapsulate_stream_data(server_data, wing::WS_OPCODE_TEXT, "Server response payload", false);

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

fn test_priority_parsing(t: core::T&) {
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
    };
}

fn test_priority_serialization(t: core::T&) {
    t.run("Priority Header Serialization") { sub =>
        var out: u8[>..] = [];

        var p1 = wing::HttpPriority { urgency: 0, incremental: true };
        wing::serialize_http_priority(p1, out);
        sub.assert_eq(out[..], "u=0, i", "Serialized u=0, i");

        out.clear();
        var p2 = wing::HttpPriority { urgency: 5, incremental: false };
        wing::serialize_http_priority(p2, out);
        sub.assert_eq(out[..], "u=5", "Serialized u=5");
    };
}

fn test_h2_priority_update_frame(t: core::T&) {
    t.run("HTTP/2 PRIORITY_UPDATE Frame (RFC 9218 §7.1)") { sub =>
        var frame_buf: u8[>..] = [];
        let prio = wing::HttpPriority { urgency: 1, incremental: true };
        internal::encode_priority_update_payload(5, prio, frame_buf);

        sub.assert_gt(frame_buf.len, 4, "Frame payload encoded");

        let stream_id, parsed_prio, err = internal::parse_priority_update_payload(frame_buf[..]);
        sub.assert_eq(err, internal::ERR_NO_ERROR, "No protocol error");
        sub.assert_eq(stream_id, 5, "Stream ID matches 5");
        sub.assert_eq(parsed_prio.urgency, 1, "Urgency matches 1");
        sub.assert_true(parsed_prio.incremental, "Incremental matches true");

        // Stream ID 0 rejection (RFC 9218 §7.1)
        var zero_id_buf: u8[8] = [0, 0, 0, 0, 'u' as u8, '=' as u8, '2' as u8, 0];
        let _, _, err_zero = internal::parse_priority_update_payload(zero_id_buf[..]);
        sub.assert_eq(err_zero, internal::ERR_PROTOCOL_ERROR, "Stream 0 rejected with PROTOCOL_ERROR");

        // Truncated payload (< 4 bytes)
        var trunc_buf: u8[2] = [0, 1];
        let _, _, err_trunc = internal::parse_priority_update_payload(trunc_buf[..]);
        sub.assert_eq(err_trunc, internal::ERR_FRAME_SIZE_ERROR, "Truncated frame rejected with FRAME_SIZE_ERROR");
    };
}

fn test_h3_priority_update_integration(t: core::T&) {
    t.run("HTTP/3 PRIORITY_UPDATE Control Frame (RFC 9218 §7.2)") { sub =>
        // Create an H3Connection with a request stream
        var conn = internal::H3Connection { .. };
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
        let new_prio = wing::HttpPriority { urgency: 0, incremental: true };
        let enc_ok = internal::encode_h3_priority_update_request(update_buf, req_id, new_prio);
        sub.assert_true(enc_ok, "Encoded H3 PRIORITY_UPDATE frame");

        // Deliver control stream type 0x00 and SETTINGS frame to initialize control stream
        conn.peer_control_stream_id = 3;
        var init_ctrl: u8[>..] = [];
        init_ctrl.push(0x00 as u8); // Control stream type
        var settings = wing::H3Settings { .. };
        internal::encode_h3_settings_frame(init_ctrl, settings);
        let err_init = internal::handle_stream_data(conn, 3, false, init_ctrl[..], false);
        sub.assert_eq(err_init, internal::H3_ERR_NO_ERROR, "Control stream initialized");

        // Now deliver PRIORITY_UPDATE frame on unidirectional stream 3
        let err_pu = internal::handle_stream_data(conn, 3, false, update_buf[..], false);
        sub.assert_eq(err_pu, internal::H3_ERR_NO_ERROR, "PRIORITY_UPDATE handled cleanly");

        // Verify that stream 0 priority has been dynamically updated!
        let updated_prio, ok_up = internal::get_stream_priority(conn, req_id);
        sub.assert_true(ok_up, "Updated priority retrieved");
        sub.assert_eq(updated_prio.urgency, 0, "Urgency dynamically updated to 0");
        sub.assert_true(updated_prio.incremental, "Incremental dynamically updated to true");
    };
}

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame
// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame
fn test_h2_extension_frames(t: core::T&) {
    t.run("ORIGIN-01: FRAME_ORIGIN serialization and multi-origin parsing") { sub =>
        var origins: const u8[:][..16] = [];
        origins.push("https://example.com");
        origins.push("https://api.example.com");

        var wire: u8[>..] = [];
        let enc_ok = internal::encode_origin_frame(wire, origins);
        sub.assert_true(enc_ok, "encode_origin_frame succeeded");

        // Parse 9-byte header
        let hdr, hdr_err = internal::parse_frame_header(wire[..9]);
        sub.assert_eq(hdr_err, internal::ERR_NO_ERROR, "frame header parsed without error");
        sub.assert_eq(hdr.frame_type, internal::FRAME_ORIGIN, "frame type is FRAME_ORIGIN (0x0C)");
        sub.assert_eq(hdr.stream_id, 0, "stream id is 0");

        // Parse payload
        var parsed_origins: const u8[:][..16] = [];
        let count, parse_err = internal::parse_origin_frame(wire[9..9 + hdr.length], hdr.stream_id, parsed_origins);
        sub.assert_eq(parse_err, internal::ERR_NO_ERROR, "payload parsed without error");
        sub.assert_eq(count, 2, "parsed 2 origins");
        sub.assert_eq(parsed_origins[0], "https://example.com", "origin 0 matched");
        sub.assert_eq(parsed_origins[1], "https://api.example.com", "origin 1 matched");
    };

    t.run("ORIGIN-02: Stream ID != 0 violation triggers PROTOCOL_ERROR") { sub =>
        let dummy_payload: u8[10] = [0x00, 0x08, 'h', 't', 't', 'p', 's', ':', '/', '/'];
        var parsed: const u8[:][..16] = [];
        let _, err = internal::parse_origin_frame(dummy_payload[..], 1, parsed);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "ORIGIN frame on stream 1 returns PROTOCOL_ERROR");

        let bad_hdr = internal::FrameHeader {
            length: 10,
            frame_type: internal::FRAME_ORIGIN,
            flags: 0,
            stream_id: 3,
        };
        let rule_err = internal::validate_frame_header_rules(bad_hdr);
        sub.assert_eq(rule_err, internal::ERR_PROTOCOL_ERROR, "validate_frame_header_rules rejects ORIGIN on stream 3");
    };

    t.run("ALTSVC-01: FRAME_ALTSVC on stream 0 with origin") { sub =>
        var wire: u8[>..] = [];
        let enc_ok = internal::encode_altsvc_frame(wire, "example.com", "h3=\":443\"; ma=86400", 0);
        sub.assert_true(enc_ok, "encode_altsvc_frame succeeded");

        let hdr, hdr_err = internal::parse_frame_header(wire[..9]);
        sub.assert_eq(hdr_err, internal::ERR_NO_ERROR, "header parsed ok");
        sub.assert_eq(hdr.frame_type, internal::FRAME_ALTSVC, "frame type is FRAME_ALTSVC (0x0A)");
        sub.assert_eq(hdr.stream_id, 0, "stream id is 0");

        let altsvc, parse_err = internal::parse_altsvc_frame(wire[9..9 + hdr.length], hdr.stream_id);
        sub.assert_eq(parse_err, internal::ERR_NO_ERROR, "parsed without error");
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
        sub.assert_eq(parse_err, internal::ERR_NO_ERROR, "parsed without error");
        sub.assert_eq(altsvc.origin.len, 0, "origin is empty on stream > 0");
        sub.assert_eq(altsvc.alt_svc_value, "h3=\":443\"", "alt_svc_value matched");
    };

    t.run("ALTSVC-03: Empty origin on stream 0 triggers PROTOCOL_ERROR") { sub =>
        let payload: u8[6] = [0x00, 0x00, 'h', '3', '=', '1'];
        let _, err = internal::parse_altsvc_frame(payload[..], 0);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "empty origin on stream 0 is PROTOCOL_ERROR");
    };

    t.run("ALTSVC-04: Non-zero origin on stream > 0 triggers PROTOCOL_ERROR") { sub =>
        let payload: u8[8] = [0x00, 0x02, 'o', 'k', 'h', '3', '=', '1'];
        let _, err = internal::parse_altsvc_frame(payload[..], 1);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "non-empty origin on stream 1 is PROTOCOL_ERROR");
    };

    t.run("ALTSVC-05: Server Ingress handles ORIGIN and ALTSVC extension frames") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(internal::H2_CLIENT_PREFACE[..]);

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

fn main() {
    var runner = core::new_runner("HTTP/2 Protocol, Multiplexing, HPACK, and RFC Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. HPACK Huffman FSM & RFC 7541 Integer Codec", test_hpack_huffman_and_integer_codec);
    core::run_case(runner, "2. HPACK Dynamic Table & Header Block Conformance", test_hpack_dynamic_table_and_header_blocks);
    core::run_case(runner, "3. Binary Framing & RFC 9218 Extensible Prioritization", test_binary_framing_and_rfc9218);
    core::run_case(runner, "4. Two-Level Signed Flow Control & Negative Windows", test_flow_control_and_session_state);
    core::run_case(runner, "5. RFC 9218 Extensible Write Scheduler", test_rfc9218_write_scheduler);
    core::run_case(runner, "6. Anti-DoS Engine & Resource Quota Protections", test_anti_dos_mitigations);
    core::run_case(runner, "7. Preface, Handshake & Settings Negotiation", test_h2_handshake_and_settings);
    core::run_case(runner, "8. Stream Multiplexing & Pipeline Dispatch", test_h2_request_dispatch);
    core::run_case(runner, "9. HttpServer End-to-End HTTP/2 Integration", test_h2_server_wire_integration);
    core::run_case(runner, "10. CONTINUATION Assembly, Anti-DoS & Rapid Reset", test_h2_continuation_and_anti_dos);
    core::run_case(runner, "11. RFC 9113 Protocol Invariants & Zero-Allocation Ingress", test_h2_protocol_invariants);
    core::run_case(runner, "12. CONTINUATION Flood & Interleaving Guard (CVE-2024-27983)", test_continuation_flood_and_interleaving);
    core::run_case(runner, "13. Rapid Reset & Resource DoS Floods (CVE-2023-44487 & CVE-2019-9512)", test_rapid_reset_and_dos_floods);
    core::run_case(runner, "14. SETTINGS & Stream ID Invariants", test_settings_and_stream_id_invariants);
    core::run_case(runner, "15. Frame Header Parsing & Type Mapping (RFC 9113)", test_h2_wire_framing_and_types);
    core::run_case(runner, "16. SETTINGS & PING Frame Wire Invariants (RFC 9113 §6.5/§6.7)", test_h2_settings_and_ping_invariants);
    core::run_case(runner, "17. Flow Control Window Arithmetic & Overflow Guards (RFC 9113 §6.9)", test_h2_window_update_and_flow_control);
    core::run_case(runner, "18. CONTINUATION Flood & Interleaving Defenses (RFC 9113 §4.3/§6.10)", test_h2_continuation_flood_and_interleaving);
    core::run_case(runner, "19. HPACK Variable-Length Integer Codec Overflows (FIND-401)", test_hpack_integer_codec_overflows);
    core::run_case(runner, "20. HPACK Dynamic Table Invariants, Eviction & Wrap-Around", test_hpack_dynamic_table_invariants);
    core::run_case(runner, "21. RFC 9113 Header Block Security Rules & Invariants", test_hpack_rfc9113_header_block_rules);
    core::run_case(runner, "22. Extended CONNECT Detection", test_extended_connect_detection);
    core::run_case(runner, "23. H3 WebSocket Formatting & Validation", test_h3_websocket_formatting);
    core::run_case(runner, "24. H3 Server Upgrade (200 OK)", test_h3_server_upgrade);
    core::run_case(runner, "25. Stream Frame Encapsulation", test_stream_frame_encapsulation);
    core::run_case(runner, "26. Priority Parsing", test_priority_parsing);
    core::run_case(runner, "27. Priority Serialization", test_priority_serialization);
    core::run_case(runner, "28. H2 Priority Update Frame", test_h2_priority_update_frame);
    core::run_case(runner, "29. H3 Priority Update Integration", test_h3_priority_update_integration);
    core::run_case(runner, "30. HTTP/2 FRAME_ORIGIN & FRAME_ALTSVC (RFC 8336 & RFC 7838)", test_h2_extension_frames);

    let ok = core::finish(runner);
    assert(ok);
}
