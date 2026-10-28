// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 Echelon 6 Conformance & Reference Suite (RFC 7541, RFC 9113, RFC 9218).
// Tests HPACK Huffman FSM, Zero-Allocation Dynamic Table, Binary Framing,
// Two-Level Signed Flow Control, RFC 9218 Write Scheduler, and Anti-DoS Defenses.
import std;
import core from "..";
import wing from "..";

// 1. HPACK Huffman FSM & RFC 7541 Integer Codec Tests
fn test_hpack_huffman_and_integer_codec(t: core::T&) {
    t.run("HPACK-01: RFC 7541 Appendix C.2 Huffman Decode Vectors") { sub =>
        // Vector 1: "www.example.com"
        let enc_www: u8[12] = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        var dec_www: u8[..64] = [];
        let ok_www = wing::decode_huffman_exact(enc_www[..], dec_www);
        sub.assert_true(ok_www, "decode www.example.com succeeds");
        sub.assert_eq(dec_www[..], "www.example.com", "decoded string matches RFC 7541 vector");

        // Vector 2: "no-cache"
        let enc_nc: u8[6] = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        var dec_nc: u8[..64] = [];
        let ok_nc = wing::decode_huffman_exact(enc_nc[..], dec_nc);
        sub.assert_true(ok_nc, "decode no-cache succeeds");
        sub.assert_eq(dec_nc[..], "no-cache", "decoded string matches RFC 7541 vector");

        // Vector 3: "custom-key" (RFC 7541 Appendix C.2.3)
        let enc_ck: u8[8] = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        var dec_ck: u8[..64] = [];
        let ok_ck = wing::decode_huffman_exact(enc_ck[..], dec_ck);
        sub.assert_true(ok_ck, "decode custom-key succeeds");
        sub.assert_eq(dec_ck[..], "custom-key", "decoded string matches RFC 7541 vector");

        // Vector 4: "custom-value"
        let enc_cv: u8[9] = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
        var dec_cv: u8[..64] = [];
        let ok_cv = wing::decode_huffman_exact(enc_cv[..], dec_cv);
        sub.assert_true(ok_cv, "decode custom-value succeeds");
        sub.assert_eq(dec_cv[..], "custom-value", "decoded string matches RFC 7541 vector");
    };

    t.run("HPACK-02: Huffman Encode / Decode Roundtrip") { sub =>
        let test_str: const u8[:] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        var encoded: u8[..128] = [];
        wing::huff_encode_bytes(test_str, encoded);
        sub.assert_true(encoded.len > 0, "encoded length > 0");
        sub.assert_true(encoded.len < test_str.len, "huffman achieves compression");

        var decoded: u8[..128] = [];
        let ok_round = wing::decode_huffman_exact(encoded[..], decoded);
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
        let ok_bad = wing::decode_huffman_exact(bad_pad[..], out_bad);
        sub.assert_false(ok_bad, "non-1s padding bits must be rejected");

        // Padding strictly longer than 7 bits must fail.
        let overlong_pad: u8[3] = [0xff, 0xff, 0xff];
        var out_over: u8[..64] = [];
        let ok_over = wing::decode_huffman_exact(overlong_pad[..], out_over);
        sub.assert_false(ok_over, "overlong padding > 7 bits must be rejected");
    };

    t.run("HPACK-04: Integer Shift Overflow Guard (Trail of Bits FIND-401 / CVE-2022-41723)") { sub =>
        // 5-bit prefix with excessive continuation bytes (shift >= 28)
        let malformed_int: u8[8] = [
            0x1F, // 5 bits all 1s
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00,
        ];
        let val, next_off, ok = wing::hpack_decode_int(malformed_int[..], 0, 5);
        sub.assert_false(ok, "integer exceeding 28 bits shift must fail cleanly without integer overflow");
    };

    t.run("HPACK-05: Integer Codec Multi-Prefix Roundtrip") { sub =>
        // Fits in prefix: 10 with 5-bit prefix
        var buf: u8[..32] = [];
        wing::hpack_encode_int(buf, 10, 5, 0x20);
        let val1, off1, ok1 = wing::hpack_decode_int(buf[..], 0, 5);
        sub.assert_true(ok1, "single byte int decode succeeds");
        sub.assert_eq(val1, 10, "value 10 matches");

        // Multi-byte int: 1337 with 6-bit prefix
        buf.clear();
        wing::hpack_encode_int(buf, 1337, 6, 0x40);
        let val2, off2, ok2 = wing::hpack_decode_int(buf[..], 0, 6);
        sub.assert_true(ok2, "multi-byte int decode succeeds");
        sub.assert_eq(val2, 1337, "value 1337 matches");
    };
}

// 2. HPACK Dynamic Table & Header Block Conformance Tests
fn test_hpack_dynamic_table_and_header_blocks(t: core::T&) {
    t.run("DYN-01: Insertion, LIFO Indexing & FIFO Eviction") { sub =>
        var dt = wing::new_dynamic_table(256); // small capacity for quick eviction

        // Insert first entry (32 overhead + 6 + 1 = 39 bytes)
        wing::insert_header(dt, "custom", "1");
        sub.assert_eq(dt.count, 1, "count is 1");
        sub.assert_eq(dt.used_bytes, 39, "used_bytes is 39");

        // Dynamic table index 62 must point to custom:1
        var n1: u8[..32] = [];
        var v1: u8[..32] = [];
        let ok_g1 = wing::get_indexed_header(dt, 62, n1, v1);
        sub.assert_true(ok_g1, "get index 62");
        sub.assert_eq(n1[..], "custom", "name matches");
        sub.assert_eq(v1[..], "1", "val matches");

        // Insert second entry (32 overhead + 6 + 1 = 39 bytes -> total 78 bytes)
        wing::insert_header(dt, "custom", "2");
        sub.assert_eq(dt.count, 2, "count is 2");
        sub.assert_eq(dt.used_bytes, 78, "used_bytes is 78");

        // LIFO external indexing: index 62 is "custom:2", index 63 is "custom:1"
        var n2: u8[..32] = [];
        var v2: u8[..32] = [];
        wing::get_indexed_header(dt, 62, n2, v2);
        sub.assert_eq(v2[..], "2", "index 62 is newest entry");

        var n3: u8[..32] = [];
        var v3: u8[..32] = [];
        wing::get_indexed_header(dt, 63, n3, v3);
        sub.assert_eq(v3[..], "1", "index 63 is older entry");
    };

    t.run("DYN-02: Zero-Allocation In-Place Compaction Invariant") { sub =>
        var dt = wing::new_dynamic_table(4096);
        // Force insertions that push arena_write_pos near 4096
        var i: u32 = 0;
        while i < 60 {
            wing::insert_header(dt, "x-header-key", "some-fixed-value-to-consume-arena-bytes");
            i++;
        }
        sub.assert_true(dt.count > 0, "entries successfully inserted");
        // Verify lookup still returns valid headers after arena usage
        var name_buf: u8[..32] = [];
        var val_buf: u8[..64] = [];
        let ok = wing::get_indexed_header(dt, 62, name_buf, val_buf);
        sub.assert_true(ok, "lookup after high-volume insertion succeeds");
        sub.assert_eq(name_buf[..], "x-header-key", "header name intact");
    };

    t.run("DYN-03: Header Block Decode with Pseudo-Headers (RFC 9113 Section 8.3)") { sub =>
        var dt = wing::new_dynamic_table(4096);

        // Encode block:
        // 1. Indexed :method: GET (static index 2 -> 0x82)
        // 2. Indexed :scheme: https (static index 7 -> 0x87)
        // 3. Indexed :path: / (static index 4 -> 0x84)
        let raw_block: u8[3] = [0x82, 0x87, 0x84];
        var out = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "valid pseudo-headers decode with NO_ERROR");
        sub.assert_eq(out.fields.len, 3, "3 fields decoded");
        sub.assert_eq(out.fields[0].name[..], ":method", "method field");
        sub.assert_eq(out.fields[0].value[..], "GET", "GET value");
    };

    t.run("DYN-04: Pseudo-Header Ordering Violation Rejection (RFC 9113 Section 8.3)") { sub =>
        var dt = wing::new_dynamic_table(4096);
        // Block:
        // 1. Regular header: accept: */* (static index 19 -> 0x93)
        // 2. Pseudo header: :path: / (static index 4 -> 0x84)  <-- ILLEGAL: pseudo after regular!
        let raw_block: u8[2] = [0x93, 0x84];
        var out = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "pseudo-header after regular header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-05: Duplicate Pseudo-Header Rejection") { sub =>
        var dt = wing::new_dynamic_table(4096);
        // Block: duplicate :method: GET (0x82, 0x82)
        let raw_block: u8[2] = [0x82, 0x82];
        var out = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "duplicate pseudo-header must trigger PROTOCOL_ERROR");
    };

    t.run("DYN-06: Content-Length Consistency & Smuggling Guard (CVE-2026-78660)") { sub =>
        var dt = wing::new_dynamic_table(4096);

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

        var out = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "conflicting Content-Length headers must trigger PROTOCOL_ERROR");

        // Identical matching Content-Length: "10" and "10" must be accepted
        raw_block.clear();
        raw_block.push(0x83);
        raw_block.push(0x00); raw_block.push(14); raw_block.append("content-length"); raw_block.push(2); raw_block.append("10");
        raw_block.push(0x00); raw_block.push(14); raw_block.append("content-length"); raw_block.push(2); raw_block.append("10");

        var out_ok = wing::DecodedH2HeaderList { .. };
        let err_ok = wing::decode_hpack_header_block(dt, raw_block[..], out_ok);
        sub.assert_eq(err_ok, wing::ERR_NO_ERROR, "identical multiple Content-Length headers are accepted");
    };

    t.run("DYN-07: Forbidden Connection Headers Rejection (RFC 9113 Section 8.2.2)") { sub =>
        var dt = wing::new_dynamic_table(4096);
        // Literal header "connection": "close"
        var raw_block: u8[..32] = [];
        raw_block.push(0x00);
        raw_block.push(10);
        raw_block.append("connection");
        raw_block.push(5);
        raw_block.append("close");

        var out = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt, raw_block[..], out);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "forbidden 'connection' header must trigger PROTOCOL_ERROR");
    };
}

// 3. Binary Framing & RFC 9218 Structured Field Prioritization Tests
fn test_binary_framing_and_rfc9218(t: core::T&) {
    t.run("FRAME-01: 9-Byte Frame Header Codec Roundtrip") { sub =>
        let orig_hdr = wing::FrameHeader {
            length: 16384,
            frame_type: wing::FRAME_DATA,
            flags: wing::FLAG_END_STREAM,
            stream_id: 101,
        };

        var buf: u8[9] = [0; 9];
        wing::encode_frame_header(orig_hdr, buf);
        sub.assert_eq(buf.len, 9, "frame header is exactly 9 bytes");

        let parsed_hdr, err = wing::parse_frame_header(buf[..]);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "parse_frame_header succeeds");
        sub.assert_eq(parsed_hdr.length, 16384, "payload length matches");
        sub.assert_eq(parsed_hdr.frame_type, wing::FRAME_DATA, "frame type matches");
        sub.assert_eq(parsed_hdr.flags, wing::FLAG_END_STREAM, "flags match");
        sub.assert_eq(parsed_hdr.stream_id, 101, "stream id matches");
    };

    t.run("FRAME-02: PADDED Payload Extraction") { sub =>
        let hdr = wing::FrameHeader {
            length: 12,
            frame_type: wing::FRAME_DATA,
            flags: wing::FLAG_PADDED,
            stream_id: 1,
        };
        // Payload: 1 byte pad length (3), 8 bytes data, 3 bytes padding
        let payload: u8[12] = [
            0x03,                                           // Pad length: 3
            'h', 'e', 'l', 'l', 'o', '!', '!', '!',         // 8 bytes data
            0x00, 0x00, 0x00,                               // 3 bytes padding
        ];

        let unpadded, err = wing::extract_padded_frame_payload(hdr, payload[..]);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "extract padding succeeds");
        sub.assert_eq(unpadded.len, 8, "unpadded length is 8");
        sub.assert_eq(unpadded, "hello!!!", "unpadded data intact");

        // Invalid padding length: pad_len (15) > length (12) -> PROTOCOL_ERROR
        let bad_payload: u8[12] = [0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let _, bad_err = wing::extract_padded_frame_payload(hdr, bad_payload[..]);
        sub.assert_eq(bad_err, wing::ERR_PROTOCOL_ERROR, "oversized padding triggers PROTOCOL_ERROR");
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
        wing::encode_priority_update_payload(42, prio, payload);

        let stream_id, parsed_prio, err = wing::parse_priority_update_payload(payload[..]);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "parse_priority_update succeeds");
        sub.assert_eq(stream_id, 42, "stream id matches 42");
        sub.assert_eq(parsed_prio.urgency, 1, "urgency matches 1");
        sub.assert_true(parsed_prio.incremental, "incremental is true");
    };

    t.run("FRAME-05: SETTINGS Parameter Boundary Validation") { sub =>
        // MAX_FRAME_SIZE below 16384 -> PROTOCOL_ERROR
        sub.assert_eq(wing::validate_settings_parameter(wing::SETTING_MAX_FRAME_SIZE, 1000), wing::ERR_PROTOCOL_ERROR);
        // MAX_FRAME_SIZE above 16777215 -> PROTOCOL_ERROR
        sub.assert_eq(wing::validate_settings_parameter(wing::SETTING_MAX_FRAME_SIZE, 20000000), wing::ERR_PROTOCOL_ERROR);
        // Valid MAX_FRAME_SIZE 65536 -> NO_ERROR
        sub.assert_eq(wing::validate_settings_parameter(wing::SETTING_MAX_FRAME_SIZE, 65536), wing::ERR_NO_ERROR);

        // INITIAL_WINDOW_SIZE > 0x7FFFFFFF -> FLOW_CONTROL_ERROR
        sub.assert_eq(wing::validate_settings_parameter(wing::SETTING_INITIAL_WINDOW_SIZE, 0x80000000), wing::ERR_FLOW_CONTROL_ERROR);

        // ENABLE_PUSH must be 0 or 1
        sub.assert_eq(wing::validate_settings_parameter(wing::SETTING_ENABLE_PUSH, 2), wing::ERR_PROTOCOL_ERROR);
        sub.assert_eq(wing::validate_settings_parameter(wing::SETTING_ENABLE_PUSH, 1), wing::ERR_NO_ERROR);
    };
}

// 4. Two-Level Signed Flow Control & Negative Window Invariant Tests
fn test_flow_control_and_session_state(t: core::T&) {
    t.run("FLOW-01: Signed Window Deltas & Negative Window State (RFC 9113 Section 6.9.2)") { sub =>
        var sess = wing::new_session_state();

        // 1. Open stream 1
        let hdr_open = wing::FrameHeader {
            length: 10,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 1,
        };
        let err_open = wing::on_ingress_frame_header(sess, hdr_open, 0);
        sub.assert_eq(err_open, wing::ERR_NO_ERROR, "open stream 1");
        sub.assert_eq(sess.streams[0].send_window, 65535, "initial send window is 65535");

        // 2. Peer decreases SETTINGS_INITIAL_WINDOW_SIZE from 65535 to 10000 (delta = -55535)
        let err_delta1 = wing::apply_peer_initial_window_size_delta(sess, 10000);
        sub.assert_eq(err_delta1, wing::ERR_NO_ERROR, "apply initial window delta 10000");
        sub.assert_eq(sess.streams[0].send_window, 10000, "stream window reduced to 10000");

        // 3. Peer decreases SETTINGS_INITIAL_WINDOW_SIZE by another 20000 to 0 (delta = -10000)
        // Then stream sends 5000 bytes so window is 5000, then delta brings it negative!
        sess.streams[0].send_window = 5000;
        let err_delta2 = wing::apply_peer_initial_window_size_delta(sess, 0);
        sub.assert_eq(err_delta2, wing::ERR_NO_ERROR, "initial window delta to 0");
        sub.assert_eq(sess.streams[0].send_window, -5000, "stream window is legitimately negative (-5000)");

        // 4. While stream send window is negative, effective quota must be 0
        let quota = wing::compute_stream_send_quota(sess, 1);
        sub.assert_eq(quota, 0, "quota with negative window is 0");

        // 5. WINDOW_UPDATE restores stream window to positive (+3000)
        let err_up = wing::apply_window_update(sess, 1, 8000);
        sub.assert_eq(err_up, wing::ERR_NO_ERROR, "window update +8000");
        sub.assert_eq(sess.streams[0].send_window, 3000, "stream window restored to +3000");

        let quota_restored = wing::compute_stream_send_quota(sess, 1);
        sub.assert_eq(quota_restored, 3000, "quota is now 3000");
    };

    t.run("FLOW-02: Window Update Overflow Rejection (Go #58456)") { sub =>
        var sess = wing::new_session_state();
        // Conn send window is 65535. Adding 0x7FFFFFFF will overflow > 2^31 - 1
        let err_ovf = wing::apply_window_update(sess, 0, 0x7FFFFFFF);
        sub.assert_eq(err_ovf, wing::ERR_FLOW_CONTROL_ERROR, "window update causing overflow must trigger FLOW_CONTROL_ERROR");

        // Window update with increment = 0 -> PROTOCOL_ERROR
        let err_zero = wing::apply_window_update(sess, 0, 0);
        sub.assert_eq(err_zero, wing::ERR_PROTOCOL_ERROR, "window update increment 0 must trigger PROTOCOL_ERROR");
    };
}

// 5. RFC 9218 Extensible Write Scheduler Tests
fn test_rfc9218_write_scheduler(t: core::T&) {
    t.run("SCHED-01: Urgency 0..7 Priority Ordering") { sub =>
        var sess = wing::new_session_state();

        // Open stream 1 (urgency 3 by default)
        let h1 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h1, 0);

        // Open stream 3 (set to urgency 0 - urgent)
        let h3 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 3 };
        wing::on_ingress_frame_header(sess, h3, 0);
        wing::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 0, incremental: false });

        sess.streams[0].pending_send_bytes = 1000; // stream 1
        sess.streams[1].pending_send_bytes = 1000; // stream 3

        // Schedule next write: Stream 3 (urgency 0) MUST be scheduled before Stream 1 (urgency 3)
        let target_id, send_len, ok = wing::schedule_next_write(sess, 16384);
        sub.assert_true(ok, "schedule succeeds");
        sub.assert_eq(target_id, 3, "urgency 0 stream scheduled first");
        sub.assert_eq(send_len, 1000, "1000 bytes sent");
    };

    t.run("SCHED-02: Starvation Prevention Between Incremental and Non-Incremental") { sub =>
        var sess = wing::new_session_state();

        // Stream 1: urgency 1, non-incremental, 2000 bytes
        let h1 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h1, 0);
        wing::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 1, incremental: false });
        sess.streams[0].pending_send_bytes = 2000;

        // Stream 3: urgency 1, incremental, 2000 bytes
        let h3 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 3 };
        wing::on_ingress_frame_header(sess, h3, 0);
        wing::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 1, incremental: true });
        sess.streams[1].pending_send_bytes = 2000;

        // Frame slice size 500
        let id1, _, _ = wing::schedule_next_write(sess, 500);
        let id2, _, _ = wing::schedule_next_write(sess, 500);

        // One must be 1, the other 3 (alternating turns)
        sub.assert_true(id1 != id2, "scheduler alternates turns between incremental and non-incremental streams");
        sub.assert_true((id1 == 1 && id2 == 3) || (id1 == 3 && id2 == 1), "both streams get scheduled in turn");
    };

    t.run("SCHED-03: Round-Robin Multiplexing Among Concurrent Incremental Streams (RFC 9218 §2.2)") { sub =>
        var sess = wing::new_session_state();

        // Stream 1: urgency 2, incremental, 1000 bytes
        let h1 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h1, 0);
        wing::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 2, incremental: true });
        sess.streams[0].pending_send_bytes = 1000;

        // Stream 3: urgency 2, incremental, 1000 bytes
        let h3 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 3 };
        wing::on_ingress_frame_header(sess, h3, 0);
        wing::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 2, incremental: true });
        sess.streams[1].pending_send_bytes = 1000;

        // Schedule round 1 & 2: each stream should get scheduled in round-robin order
        let id1, _, ok1 = wing::schedule_next_write(sess, 200);
        let id2, _, ok2 = wing::schedule_next_write(sess, 200);
        let id3, _, ok3 = wing::schedule_next_write(sess, 200);
        let id4, _, ok4 = wing::schedule_next_write(sess, 200);

        sub.assert_true(ok1 && ok2 && ok3 && ok4, "all 4 scheduling rounds succeeded");
        sub.assert_eq(id1, 1, "first round-robin choice is stream 1");
        sub.assert_eq(id2, 3, "second round-robin choice is stream 3");
        sub.assert_eq(id3, 1, "third round-robin choice rotates back to stream 1");
        sub.assert_eq(id4, 3, "fourth round-robin choice rotates back to stream 3");
    };

    t.run("SCHED-04: Anti-Starvation Credit Yield Across Urgency Levels") { sub =>
        var sess = wing::new_session_state();

        // Stream 1: high urgency 0, non-incremental, large payload (20000 bytes)
        let h1 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h1, 0);
        wing::apply_priority_update(sess, 1, wing::PriorityParam { urgency: 0, incremental: false });
        sess.streams[0].pending_send_bytes = 20000;

        // Stream 3: lower urgency 3, non-incremental, small payload (500 bytes)
        let h3 = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 3 };
        wing::on_ingress_frame_header(sess, h3, 0);
        wing::apply_priority_update(sess, 3, wing::PriorityParam { urgency: 3, incremental: false });
        sess.streams[1].pending_send_bytes = 500;

        // Run 16 consecutive frames for stream 1
        for i in 16 {
            let id, _, ok = wing::schedule_next_write(sess, 100);
            sub.assert_true(ok, "scheduled high urgency frame");
            sub.assert_eq(id, 1, "stream 1 scheduled");
        }

        // Frame 17 MUST trigger anti-starvation yield to lower urgency stream 3!
        let id17, _, ok17 = wing::schedule_next_write(sess, 100);
        sub.assert_true(ok17, "frame 17 scheduled");
        sub.assert_eq(id17, 3, "frame 17 yielded to lower-urgency stream 3 to prevent starvation");
    };
}

// 6. Anti-DoS Engine & Resource Quota Tests
fn test_anti_dos_mitigations(t: core::T&) {
    t.run("DOS-01: Rapid Reset Token Bucket Defense (CVE-2023-44487)") { sub =>
        // Session with small reset burst = 5
        var sess = wing::SessionState {
            reset_limiter: wing::new_h2_token_bucket(5, 1, 0),
            ..
        };

        // Open stream 1 then reset it
        let h_open = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h_open, 0);

        // Exhaust tokens (5 RST_STREAMs on stream 1)
        var i: u32 = 0;
        while i < 5 {
            let rst = wing::FrameHeader { length: 4, frame_type: wing::FRAME_RST_STREAM, flags: 0, stream_id: 1 };
            let err = wing::on_ingress_frame_header(sess, rst, 0);
            sub.assert_eq(err, wing::ERR_NO_ERROR, "allowed within burst limit");
            i++;
        }

        // 6th RST_STREAM without time advance -> ENHANCE_YOUR_CALM
        let rst_flood = wing::FrameHeader { length: 4, frame_type: wing::FRAME_RST_STREAM, flags: 0, stream_id: 1 };
        let err_flood = wing::on_ingress_frame_header(sess, rst_flood, 0);
        sub.assert_eq(err_flood, wing::ERR_ENHANCE_YOUR_CALM, "rapid reset flood must trigger ENHANCE_YOUR_CALM");
    };

    t.run("DOS-02: CONTINUATION Flood Guard (CVE-2024-28182)") { sub =>
        var sess = wing::new_session_state();

        // Initial HEADERS on stream 1 without END_HEADERS (enters ExpectContinuation)
        let h1 = wing::FrameHeader { length: 100, frame_type: wing::FRAME_HEADERS, flags: 0, stream_id: 1 };
        let err0 = wing::on_ingress_frame_header(sess, h1, 0);
        sub.assert_eq(err0, wing::ERR_NO_ERROR, "headers accepted");

        // Send MAX_CONT_FRAMES_LIMIT (16) CONTINUATION frames
        var i: u32 = 0;
        while i < wing::MAX_CONT_FRAMES_LIMIT {
            let c = wing::FrameHeader { length: 10, frame_type: wing::FRAME_CONTINUATION, flags: 0, stream_id: 1 };
            let err = wing::on_ingress_frame_header(sess, c, 0);
            sub.assert_eq(err, wing::ERR_NO_ERROR, "continuation within limit accepted");
            i++;
        }

        // 17th CONTINUATION frame -> ENHANCE_YOUR_CALM
        let c_flood = wing::FrameHeader { length: 10, frame_type: wing::FRAME_CONTINUATION, flags: 0, stream_id: 1 };
        let err_flood = wing::on_ingress_frame_header(sess, c_flood, 0);
        sub.assert_eq(err_flood, wing::ERR_ENHANCE_YOUR_CALM, "excess CONTINUATION frames trigger ENHANCE_YOUR_CALM");
    };

    t.run("DOS-03: Slow-Drip CONTINUATION Defense (CVE-2024-27983)") { sub =>
        var sess = wing::new_session_state(0, 8192);

        // Start CONTINUATION block at now_ms = 0
        let h1 = wing::FrameHeader { length: 10, frame_type: wing::FRAME_HEADERS, flags: 0, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h1, 0);

        // Second CONTINUATION arrives after 15,000 ms (> 10,000 ms max_header_block_duration_ms)
        let c_slow = wing::FrameHeader { length: 10, frame_type: wing::FRAME_CONTINUATION, flags: 0, stream_id: 1 };
        let err_slow = wing::on_ingress_frame_header(sess, c_slow, 15000);
        sub.assert_eq(err_slow, wing::ERR_ENHANCE_YOUR_CALM, "slow-drip header block retention triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-04: Stream Interleaving Rejection During CONTINUATION (RFC 9113 Section 6.10)") { sub =>
        var sess = wing::new_session_state();

        // HEADERS on stream 1 expecting CONTINUATION
        let h1 = wing::FrameHeader { length: 10, frame_type: wing::FRAME_HEADERS, flags: 0, stream_id: 1 };
        wing::on_ingress_frame_header(sess, h1, 0);

        // Interleaved DATA frame on stream 1
        let d = wing::FrameHeader { length: 10, frame_type: wing::FRAME_DATA, flags: 0, stream_id: 1 };
        let err_d = wing::on_ingress_frame_header(sess, d, 0);
        sub.assert_eq(err_d, wing::ERR_PROTOCOL_ERROR, "interleaved DATA frame triggers PROTOCOL_ERROR");
    };

    t.run("DOS-05: Empty Frame Flooding Defense (CVE-2019-9518)") { sub =>
        var sess = wing::new_session_state();

        // Send 8 empty DATA frames without END_STREAM (allowed)
        var i: u32 = 0;
        while i < wing::MAX_EMPTY_FRAME_STREAK {
            let empty_data = wing::FrameHeader { length: 0, frame_type: wing::FRAME_DATA, flags: 0, stream_id: 1 };
            let err = wing::on_ingress_frame_header(sess, empty_data, 0);
            sub.assert_eq(err, wing::ERR_NO_ERROR, "empty frame streak within limit");
            i++;
        }

        // 9th empty DATA frame -> ENHANCE_YOUR_CALM
        let empty_streak = wing::FrameHeader { length: 0, frame_type: wing::FRAME_DATA, flags: 0, stream_id: 1 };
        let err_streak = wing::on_ingress_frame_header(sess, empty_streak, 0);
        sub.assert_eq(err_streak, wing::ERR_ENHANCE_YOUR_CALM, "empty frame flood streak triggers ENHANCE_YOUR_CALM");
    };

    t.run("DOS-06: PING / SETTINGS Flood Defense (CVE-2019-9512 / CVE-2019-9515)") { sub =>
        var sess = wing::new_session_state();

        // Send 64 unacknowledged PING frames
        var i: u32 = 0;
        while i < wing::MAX_PENDING_CTRL_FRAMES {
            let ping = wing::FrameHeader { length: 8, frame_type: wing::FRAME_PING, flags: 0, stream_id: 0 };
            let err = wing::on_ingress_frame_header(sess, ping, 0);
            sub.assert_eq(err, wing::ERR_NO_ERROR, "ping within control frame quota");
            i++;
        }

        // 65th unacknowledged PING -> ENHANCE_YOUR_CALM
        let ping_flood = wing::FrameHeader { length: 8, frame_type: wing::FRAME_PING, flags: 0, stream_id: 0 };
        let err_flood = wing::on_ingress_frame_header(sess, ping_flood, 0);
        sub.assert_eq(err_flood, wing::ERR_ENHANCE_YOUR_CALM, "unacknowledged control frame flood triggers ENHANCE_YOUR_CALM");
    };
}

fn main() {
    var runner = core::new_runner("HTTP/2 Reference Conformance Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. HPACK Huffman FSM & RFC 7541 Integer Codec", test_hpack_huffman_and_integer_codec);
    core::run_case(runner, "2. HPACK Dynamic Table & Header Block Conformance", test_hpack_dynamic_table_and_header_blocks);
    core::run_case(runner, "3. Binary Framing & RFC 9218 Extensible Prioritization", test_binary_framing_and_rfc9218);
    core::run_case(runner, "4. Two-Level Signed Flow Control & Negative Windows", test_flow_control_and_session_state);
    core::run_case(runner, "5. RFC 9218 Extensible Write Scheduler", test_rfc9218_write_scheduler);
    core::run_case(runner, "6. Anti-DoS Engine & Resource Quota Protections", test_anti_dos_mitigations);

    let ok = core::finish(runner);
    assert(ok);
}
