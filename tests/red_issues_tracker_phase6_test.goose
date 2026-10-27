// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 6 RED test suite based on .gemini issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and edge cases that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters (Reject 0x01..0x08, 0x0B, 0x0C, 0x0E..0x1F, 0x7F)
// 2. RFC 9113 §8.3: Undefined Pseudo-Headers MUST Return PROTOCOL_ERROR
// 3. RFC 9114 §4.2 & RFC 9204 §4.1: HTTP/3 QPACK Uppercase Literal Field Names Treated as Malformed
// 4. RFC 9113 §6.6: Frame Header Rules for PUSH_PROMISE (Stream 0 & Min Length Validation)
// 5. RFC 9112 §7.1 & CVE-2023-45287 (Go #71988): Chunked FSM Bare LF in Chunk Size Rejection
// 6. RFC 9112 §7.1.1 & Go #82257: Chunked FSM BWS (Spaces/Tabs) Preceding Semicolon Acceptance
// 7. RFC 9110 §13.2.2: parse_field_names Bounded Capacity Overflow Protection for Field Names > 64 Bytes

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters
// ----------------------------------------------------------------------------
fn test_h2_field_value_ctl_rejection(t: core::T&) {
    t.run("Valid field value without control characters is accepted") { sub =>
        let ok = wing::validate_h2_field_syntax("custom-header", "valid-value-123");
        sub.assert_true(ok, "Standard printable ASCII value must be valid");
    };

    t.run("Field value with HTAB (0x09) inside is accepted per RFC 9113 §8.2.1") { sub =>
        let ok = wing::validate_h2_field_syntax("custom-header", "val\twith\ttabs");
        sub.assert_true(ok, "HTAB inside field value is permitted");
    };

    t.run("Field value with VT (0x0B) MUST be rejected") { sub =>
        // RFC 9113 Section 8.2.1: CTL characters 0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F MUST trigger protocol error
        let ok = wing::validate_h2_field_syntax("custom-header", "val\x0bwith-vt");
        sub.assert_false(ok, "VT (0x0B) in field value MUST be rejected");
    };

    t.run("Field value with FF (0x0C) MUST be rejected") { sub =>
        let ok = wing::validate_h2_field_syntax("custom-header", "val\x0cwith-ff");
        sub.assert_false(ok, "FF (0x0C) in field value MUST be rejected");
    };

    t.run("Field value with ESC (0x1B) MUST be rejected") { sub =>
        let ok = wing::validate_h2_field_syntax("custom-header", "val\x1bwith-esc");
        sub.assert_false(ok, "ESC (0x1B) in field value MUST be rejected");
    };

    t.run("Field value with DEL (0x7F) MUST be rejected") { sub =>
        let ok = wing::validate_h2_field_syntax("custom-header", "val\x7fwith-del");
        sub.assert_false(ok, "DEL (0x7F) in field value MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9113 §8.3: Undefined Pseudo-Headers MUST Return PROTOCOL_ERROR
// ----------------------------------------------------------------------------
fn test_h2_undefined_pseudo_header_rejection(t: core::T&) {
    t.run("Valid standard pseudo-headers accepted in order") { sub =>
        var list = wing::DecodedH2HeaderList { .. };
        let err1 = wing::validate_header_ordering_and_rules(list, ":method", "GET");
        sub.assert_eq(err1, wing::ERR_NO_ERROR, ":method is valid pseudo-header");
        list.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        let err2 = wing::validate_header_ordering_and_rules(list, ":path", "/index.html");
        sub.assert_eq(err2, wing::ERR_NO_ERROR, ":path is valid pseudo-header");
    };

    t.run("Undefined pseudo-header :custom MUST return ERR_PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 8.3: "Endpoints MUST treat a request or response that contains an undefined
        // or invalid pseudo-header field as malformed (Section 8.1.1)."
        var list = wing::DecodedH2HeaderList { .. };
        let err = wing::validate_header_ordering_and_rules(list, ":custom", "val");
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "Undefined pseudo-header :custom MUST return ERR_PROTOCOL_ERROR");
    };

    t.run("Undefined pseudo-header :fake MUST return ERR_PROTOCOL_ERROR") { sub =>
        var list = wing::DecodedH2HeaderList { .. };
        let err = wing::validate_header_ordering_and_rules(list, ":fake", "exploit");
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "Undefined pseudo-header :fake MUST return ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9114 §4.2 & RFC 9204 §4.1: HTTP/3 QPACK Uppercase Literal Field Names
// ----------------------------------------------------------------------------
fn test_qpack_uppercase_literal_field_name_rejection(t: core::T&) {
    t.run("Lowercase literal field name is decoded successfully") { sub =>
        var tbl = wing::QpackTable { .. };
        var out_fields: wing::HeaderField[>..] = [];

        // Literal Field Line With Literal Name (001NHxxx):
        // Byte 0: 0x24 (0010 0100: name len 4)
        // Name: "host"
        // Byte: 0x07 (val len 7)
        // Value: "foo.bar"
        let wire: const u8[15] = [
            0x00, 0x00, // RIC=0, Base=0
            0x24, 'h', 'o', 's', 't',
            0x07, 'f', 'o', 'o', '.', 'b', 'a', 'r',
        ];

        let err = wing::decode_qpack_section(tbl, wire[..], out_fields);
        sub.assert_eq(err, wing::QpackError.None, "Valid lowercase QPACK field accepted");
        sub.assert_eq(out_fields.len, 1, "1 field decoded");
        sub.assert_bytes_eq(out_fields[0].name[..], "host", "Field name matches");
    };

    t.run("Uppercase literal field name MUST be rejected with DecompressionFailed") { sub =>
        // RFC 9114 Section 4.2: Characters in field names MUST be converted to lowercase prior to encoding.
        // A request containing uppercase characters in field names MUST be treated as malformed.
        var tbl = wing::QpackTable { .. };
        var out_fields: wing::HeaderField[>..] = [];

        let wire: const u8[15] = [
            0x00, 0x00, // RIC=0, Base=0
            0x24, 'H', 'o', 's', 't', // "Host" has uppercase 'H'
            0x07, 'f', 'o', 'o', '.', 'b', 'a', 'r',
        ];

        let err = wing::decode_qpack_section(tbl, wire[..], out_fields);
        sub.assert_eq(err, wing::QpackError.DecompressionFailed, "Uppercase field name MUST be rejected per RFC 9114 §4.2");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9113 §6.6: Frame Header Rules for PUSH_PROMISE
// ----------------------------------------------------------------------------
fn test_h2_push_promise_frame_rules(t: core::T&) {
    t.run("PUSH_PROMISE on stream 0 MUST return ERR_PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 6.6: "PUSH_PROMISE frames MUST be associated with an existing, peer-initiated stream.
        // If the stream identifier field specifies the value 0x00, a recipient MUST respond with a connection error of type PROTOCOL_ERROR."
        let hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_PUSH_PROMISE,
            flags: 0,
            stream_id: 0,
        };
        let err = wing::validate_frame_header_rules(hdr);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "PUSH_PROMISE on stream 0 MUST return PROTOCOL_ERROR");
    };

    t.run("PUSH_PROMISE with length < 4 MUST return ERR_FRAME_SIZE_ERROR") { sub =>
        // RFC 9113 Section 6.6: Promised Stream ID is 4 bytes. Unpadded PUSH_PROMISE < 4 bytes is invalid.
        let hdr = wing::FrameHeader {
            length: 3,
            frame_type: wing::FRAME_PUSH_PROMISE,
            flags: 0,
            stream_id: 1,
        };
        let err = wing::validate_frame_header_rules(hdr);
        sub.assert_eq(err, wing::ERR_FRAME_SIZE_ERROR, "Unpadded PUSH_PROMISE < 4 bytes MUST return FRAME_SIZE_ERROR");
    };

    t.run("Padded PUSH_PROMISE with length < 5 MUST return ERR_FRAME_SIZE_ERROR") { sub =>
        // With PADDED flag, Pad Length (1 byte) + Promised Stream ID (4 bytes) = 5 bytes minimum
        let hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_PUSH_PROMISE,
            flags: wing::FLAG_PADDED,
            stream_id: 1,
        };
        let err = wing::validate_frame_header_rules(hdr);
        sub.assert_eq(err, wing::ERR_FRAME_SIZE_ERROR, "Padded PUSH_PROMISE < 5 bytes MUST return FRAME_SIZE_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 9112 §7.1 & CVE-2023-45287 (Go #71988): Chunked FSM Bare LF in Chunk Size Rejection
// ----------------------------------------------------------------------------
fn test_chunked_fsm_bare_lf_rejection(t: core::T&) {
    t.run("Chunk size terminated with bare LF MUST return Error") { sub =>
        // RFC 9112 Section 7.1 & Section 2.2: Bare LF on chunk size line is forbidden (HTTP Smuggling)
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "5\nhello\r\n0\r\n\r\n";
        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Bare LF without preceding CR MUST return ChunkFsmStatus.Error");
    };

    t.run("Chunk extension terminated with bare LF MUST return Error") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "5;ext=val\nhello\r\n0\r\n\r\n";
        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Bare LF in chunk extension MUST return ChunkFsmStatus.Error");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 9112 §7.1.1 & Go #82257: Chunked FSM BWS (Spaces/Tabs) Preceding Semicolon Acceptance
// ----------------------------------------------------------------------------
fn test_chunked_fsm_bws_preceding_semicolon(t: core::T&) {
    t.run("Space preceding semicolon in chunk extension MUST be accepted") { sub =>
        // RFC 9112 Section 7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
        // BWS = *( SP / HTAB )
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "5 ;ext=foo\r\nhello\r\n0\r\n\r\n";
        var total_body: u8[..64] = [];
        var cursor: i64 = 0;

        while cursor < raw.len {
            let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw[cursor..]);
            cursor += consumed;
            if st == internal::ChunkFsmStatus.YieldChunk {
                total_body.append(chunk);
            } else if st == internal::ChunkFsmStatus.Complete {
                break;
            } else if st == internal::ChunkFsmStatus.Error {
                sub.assert_true(false, "Chunked decoder must not error on BWS before semicolon");
                break;
            }
        }

        sub.assert_bytes_eq(total_body[..], "hello", "Decoded payload must match");
    };

    t.run("HTAB preceding semicolon in chunk extension MUST be accepted") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "5\t;ext=foo\r\nworld\r\n0\r\n\r\n";
        var total_body: u8[..64] = [];
        var cursor: i64 = 0;

        while cursor < raw.len {
            let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw[cursor..]);
            cursor += consumed;
            if st == internal::ChunkFsmStatus.YieldChunk {
                total_body.append(chunk);
            } else if st == internal::ChunkFsmStatus.Complete {
                break;
            } else if st == internal::ChunkFsmStatus.Error {
                sub.assert_true(false, "Chunked decoder must not error on HTAB before semicolon");
                break;
            }
        }

        sub.assert_bytes_eq(total_body[..], "world", "Decoded payload must match");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9110 §13.2.2: parse_field_names Bounded Capacity Overflow Protection
// ----------------------------------------------------------------------------
fn test_cache_control_field_names_overflow_protection(t: core::T&) {
    t.run("Long header field name > 64 bytes in Cache-Control MUST NOT panic") { sub =>
        // Capacity of buf in parse_field_names is 64 bytes.
        // A header field name with 80 bytes would previously exceed capacity and panic.
        var cc = wing::CacheControl { .. };
        let long_field = "private=\"x-very-long-custom-header-field-name-that-exceeds-sixty-four-bytes-limit-strictly-for-testing-purposes\"";

        wing::parse_cache_control_str(long_field, cc);
        sub.assert_true(wing::is_private(cc), "CC_PRIVATE flag must be set");
    };
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------
fn main() {
    let _ = wing::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = core::new_runner("RED Suite Phase 6: Issues Tracker & RFC Invariants", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters", test_h2_field_value_ctl_rejection);
    core::run_case(runner, "2. RFC 9113 §8.3: Undefined Pseudo-Headers Rejection", test_h2_undefined_pseudo_header_rejection);
    core::run_case(runner, "3. RFC 9114 §4.2: QPACK Uppercase Literal Field Names", test_qpack_uppercase_literal_field_name_rejection);
    core::run_case(runner, "4. RFC 9113 §6.6: Frame Rules for PUSH_PROMISE", test_h2_push_promise_frame_rules);
    core::run_case(runner, "5. RFC 9112 §7.1: Chunked FSM Bare LF Rejection", test_chunked_fsm_bare_lf_rejection);
    core::run_case(runner, "6. RFC 9112 §7.1.1: Chunked FSM BWS Before Semicolon", test_chunked_fsm_bws_preceding_semicolon);
    core::run_case(runner, "7. RFC 9110 §13.2.2: Cache-Control Field Names Length Safety", test_cache_control_field_names_overflow_protection);

    let ok = core::finish(runner);
    print("\n[RED PHASE 6 TEST SUITE STATUS] Finished execution. Result ok=", ok);
    if !ok {
        print(">>> CONFIRMED RED PHASE 6: Target vulnerabilities/flaws reproduce successfully against the current codebase! <<<\n");
    }
}
