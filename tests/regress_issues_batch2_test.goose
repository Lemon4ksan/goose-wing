// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Issue Regression Suite Batch 2 (Phases 6-10)
import std;
import core from "..";
import wing from "..";

// --- Component: regress_issues_batch06 ---
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

// ----------------------------------------------------------------------------
// 1. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters
// ----------------------------------------------------------------------------
fn test_h2_field_value_ctl_rejection(t: core::T&) {
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
// 2. RFC 9113 §8.3: Undefined Pseudo-Headers MUST Return PROTOCOL_ERROR
// ----------------------------------------------------------------------------
fn test_h2_undefined_pseudo_header_rejection(t: core::T&) {
    t.run("Valid standard pseudo-headers accepted in order") { sub =>
        var list = internal::DecodedH2HeaderList { .. };
        let err1 = internal::validate_header_ordering_and_rules(list, ":method", "GET");
        sub.assert_eq(err1, internal::ERR_NO_ERROR, ":method is valid pseudo-header");
        list.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        let err2 = internal::validate_header_ordering_and_rules(list, ":path", "/index.html");
        sub.assert_eq(err2, internal::ERR_NO_ERROR, ":path is valid pseudo-header");
    };

    t.run("Undefined pseudo-header :custom MUST return ERR_PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 8.3: "Endpoints MUST treat a request or response that contains an undefined
        // or invalid pseudo-header field as malformed (Section 8.1.1)."
        var list = internal::DecodedH2HeaderList { .. };
        let err = internal::validate_header_ordering_and_rules(list, ":custom", "val");
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "Undefined pseudo-header :custom MUST return ERR_PROTOCOL_ERROR");
    };

    t.run("Undefined pseudo-header :fake MUST return ERR_PROTOCOL_ERROR") { sub =>
        var list = internal::DecodedH2HeaderList { .. };
        let err = internal::validate_header_ordering_and_rules(list, ":fake", "exploit");
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "Undefined pseudo-header :fake MUST return ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9114 §4.2 & RFC 9204 §4.1: HTTP/3 QPACK Uppercase Literal Field Names
// ----------------------------------------------------------------------------
fn test_qpack_uppercase_literal_field_name_rejection(t: core::T&) {
    t.run("Lowercase literal field name is decoded successfully") { sub =>
        var tbl = internal::QpackTable { .. };
        var out_fields: internal::HeaderField[>..] = [];

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

        let err = internal::decode_qpack_section(tbl, wire[..], out_fields);
        sub.assert_eq(err, internal::QpackError.None, "Valid lowercase QPACK field accepted");
        sub.assert_eq(out_fields.len, 1, "1 field decoded");
        sub.assert_bytes_eq(out_fields[0].name[..], "host", "Field name matches");
    };

    t.run("Uppercase literal field name MUST be rejected with DecompressionFailed") { sub =>
        // RFC 9114 Section 4.2: Characters in field names MUST be converted to lowercase prior to encoding.
        // A request containing uppercase characters in field names MUST be treated as malformed.
        var tbl = internal::QpackTable { .. };
        var out_fields: internal::HeaderField[>..] = [];

        let wire: const u8[15] = [
            0x00, 0x00, // RIC=0, Base=0
            0x24, 'H', 'o', 's', 't', // "Host" has uppercase 'H'
            0x07, 'f', 'o', 'o', '.', 'b', 'a', 'r',
        ];

        let err = internal::decode_qpack_section(tbl, wire[..], out_fields);
        sub.assert_eq(err, internal::QpackError.DecompressionFailed, "Uppercase field name MUST be rejected per RFC 9114 §4.2");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9113 §6.6: Frame Header Rules for PUSH_PROMISE
// ----------------------------------------------------------------------------
fn test_h2_push_promise_frame_rules(t: core::T&) {
    t.run("PUSH_PROMISE on stream 0 MUST return ERR_PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 6.6: "PUSH_PROMISE frames MUST be associated with an existing, peer-initiated stream.
        // If the stream identifier field specifies the value 0x00, a recipient MUST respond with a connection error of type PROTOCOL_ERROR."
        let hdr = internal::FrameHeader {
            length:     4,
            frame_type: internal::FRAME_PUSH_PROMISE,
            flags:      0,
            stream_id:  0,
        };
        let err = internal::validate_frame_header_rules(hdr);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "PUSH_PROMISE on stream 0 MUST return PROTOCOL_ERROR");
    };

    t.run("PUSH_PROMISE with length < 4 MUST return ERR_FRAME_SIZE_ERROR") { sub =>
        // RFC 9113 Section 6.6: Promised Stream ID is 4 bytes. Unpadded PUSH_PROMISE < 4 bytes is invalid.
        let hdr = internal::FrameHeader {
            length:     3,
            frame_type: internal::FRAME_PUSH_PROMISE,
            flags:      0,
            stream_id:  1,
        };
        let err = internal::validate_frame_header_rules(hdr);
        sub.assert_eq(err, internal::ERR_FRAME_SIZE_ERROR, "Unpadded PUSH_PROMISE < 4 bytes MUST return FRAME_SIZE_ERROR");
    };

    t.run("Padded PUSH_PROMISE with length < 5 MUST return ERR_FRAME_SIZE_ERROR") { sub =>
        // With PADDED flag, Pad Length (1 byte) + Promised Stream ID (4 bytes) = 5 bytes minimum
        let hdr = internal::FrameHeader {
            length:     4,
            frame_type: internal::FRAME_PUSH_PROMISE,
            flags:      internal::FLAG_PADDED,
            stream_id:  1,
        };
        let err = internal::validate_frame_header_rules(hdr);
        sub.assert_eq(err, internal::ERR_FRAME_SIZE_ERROR, "Padded PUSH_PROMISE < 5 bytes MUST return FRAME_SIZE_ERROR");
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
        var cursor:     i64      = 0;

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
        var cursor:     i64      = 0;

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

// --- Component: regress_issues_batch07 ---
// Phase 7 RED test suite based on .gemini issue trackers and RFC specifications.
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
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Frame Stream ID Invariant
// ----------------------------------------------------------------------------
fn test_h2_goaway_stream_id_zero(t: core::T&) {
    t.run("GOAWAY frame on stream_id > 0 must return ERR_PROTOCOL_ERROR (RFC 9113 §6.8)") { sub =>
        // RFC 9113 Section 6.8:
        // "GOAWAY frames apply to the connection, not a specific stream, so the stream identifier
        // for a GOAWAY frame MUST be zero (0x00)."
        // "An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00
        // as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
        let bad_hdr = internal::FrameHeader {
            length:     8,
            frame_type: internal::FRAME_GOAWAY,
            flags:      0,
            stream_id:  1, // Invalid: GOAWAY MUST be on stream 0
        };
        let err = internal::validate_frame_header_rules(bad_hdr);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "GOAWAY on stream 1 MUST be rejected with PROTOCOL_ERROR (RFC 9113 §6.8)");

        let bad_hdr3 = internal::FrameHeader {
            length:     8,
            frame_type: internal::FRAME_GOAWAY,
            flags:      0,
            stream_id:  3,
        };
        let err3 = internal::validate_frame_header_rules(bad_hdr3);
        sub.assert_eq(err3, internal::ERR_PROTOCOL_ERROR, "GOAWAY on stream 3 MUST be rejected with PROTOCOL_ERROR (RFC 9113 §6.8)");

        let good_hdr = internal::FrameHeader {
            length:     8,
            frame_type: internal::FRAME_GOAWAY,
            flags:      0,
            stream_id:  0,
        };
        let ok_err = internal::validate_frame_header_rules(good_hdr);
        sub.assert_eq(ok_err, internal::ERR_NO_ERROR, "GOAWAY on stream 0 is valid");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Ignored
// ----------------------------------------------------------------------------
fn test_cookie_relative_path_ignored(t: core::T&) {
    t.run("Cookie Path attribute without leading slash MUST be ignored (RFC 6265bis §5.4)") { sub =>
        // RFC 6265bis Section 5.4:
        // "If the attribute-value is empty or if the first character of the
        // attribute-value is not %x2F ('/'):
        //   Let cookie-path be the default-path.
        // Otherwise:
        //   Let cookie-path be the attribute-value."
        var cookie = wing::CanonicalCookie { .. };
        cookie.path.clear();
        cookie.path.append("/default/api");

        // Relative path "relative/path" lacks leading '/' -> must be ignored!
        wing::apply_parsed_path_attribute(cookie, "relative/path");
        sub.assert_bytes_eq(cookie.path[..], "/default/api", "Relative Path 'relative/path' must be ignored, retaining default path");

        // Relative path "admin" lacks leading '/' -> must be ignored!
        wing::apply_parsed_path_attribute(cookie, "admin");
        sub.assert_bytes_eq(cookie.path[..], "/default/api", "Relative Path 'admin' must be ignored, retaining default path");

        // Absolute path "/valid/path" begins with '/' -> must be applied!
        wing::apply_parsed_path_attribute(cookie, "/valid/path");
        sub.assert_bytes_eq(cookie.path[..], "/valid/path", "Absolute Path '/valid/path' must be applied");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9110 §13.2.1: Cache-Control max-age Arithmetic Overflow Clamping
// ----------------------------------------------------------------------------
fn test_cache_control_max_age_overflow_clamping(t: core::T&) {
    t.run("Huge max-age delta-seconds (20+ digits) must saturate to MAX_DELTA_SECONDS without wrapping") { sub =>
        // RFC 9110 Section 13.2.1 & RFC 8941:
        // Delta-seconds directives with huge number of digits must saturate/clamp to MAX_DELTA_SECONDS
        // without 64-bit integer overflow wrap to negative numbers.
        let secs, ok = wing::parse_delta_seconds("99999999999999999999");
        sub.assert_true(ok, "Huge delta-seconds must parse successfully");
        sub.assert_gt(secs, 0, "Huge delta-seconds must be positive (no arithmetic wrap)");
        sub.assert_eq(secs, wing::MAX_DELTA_SECONDS as i32, "Huge delta-seconds must saturate to MAX_DELTA_SECONDS (2147483647)");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present
// ----------------------------------------------------------------------------
fn test_h2_connect_scheme_path_rejection(t: core::T&) {
    t.run("Standard CONNECT with :path present MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)") { sub =>
        // RFC 9113 Section 8.5:
        // "For CONNECT requests, the ':path' and ':scheme' pseudo-header fields MUST be omitted."
        // "A request that includes ':path' or ':scheme' in a CONNECT request (unless using
        // the Extended CONNECT protocol defined in RFC 8441) MUST be treated as malformed."
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "CONNECT");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method CONNECT accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "CONNECT", .. });

        let ok_auth = internal::validate_header_ordering_and_rules(headers, ":authority", "proxy.example.com:443");
        sub.assert_eq(ok_auth, internal::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":authority", value: "proxy.example.com:443", .. });

        // Standard CONNECT with :path must be rejected as PROTOCOL_ERROR!
        let err_path = internal::validate_header_ordering_and_rules(headers, ":path", "/");
        sub.assert_eq(err_path, internal::ERR_PROTOCOL_ERROR, "Standard CONNECT with :path MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)");
    };

    t.run("Standard CONNECT with :scheme present MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "CONNECT");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method CONNECT accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "CONNECT", .. });

        let ok_auth = internal::validate_header_ordering_and_rules(headers, ":authority", "proxy.example.com:443");
        sub.assert_eq(ok_auth, internal::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":authority", value: "proxy.example.com:443", .. });

        // Standard CONNECT with :scheme must be rejected as PROTOCOL_ERROR!
        let err_scheme = internal::validate_header_ordering_and_rules(headers, ":scheme", "https");
        sub.assert_eq(err_scheme, internal::ERR_PROTOCOL_ERROR, "Standard CONNECT with :scheme MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 6455 §5.5 & Go #7825: WebSocket Empty Payload Ping / Pong Roundtrip
// ----------------------------------------------------------------------------
fn test_ws_empty_payload_ping_pong(t: core::T&) {
    t.run("WebSocket Ping with 0 payload is accepted and answered with 0-payload Pong") { sub =>
        // RFC 6455 §5.5.2 & §5.5.3 / Go #7825:
        // A Ping frame MAY carry an empty application data payload (0 bytes).
        // The receiver MUST emit a Pong frame with identical 0-byte payload.
        var ws_sess = wing::new_websocket_session(true); // client
        var ping_wire: u8[>..] = [];
        let no_mask: u8[4] = [0, 0, 0, 0];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "", false, no_mask, true);

        // Frame header must have payload_len = 0
        let hdr, ok_hdr = wing::parse_ws_frame_header(ping_wire[..]);
        sub.assert_true(ok_hdr, "Empty Ping header parsed");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_PING, "Opcode is PING");
        sub.assert_eq(hdr.payload_len, 0, "Payload length is 0");

        var msg = wing::WsMessage { .. };
        var pong_reply: u8[>..] = [];
        let handled = ws_sess.receive(ping_wire[..], msg, pong_reply);
        sub.assert_true(handled, "receive processed empty Ping frame");
        sub.assert_eq(msg.opcode, wing::WS_OPCODE_PING, "Message opcode is PING");
        sub.assert_eq(msg.data.len, 0, "Ping message payload is 0 bytes");

        // Outbound Pong response must also be empty payload
        sub.assert_ge(pong_reply.len, 2, "Outbound Pong reply frame emitted");
        let pong_hdr, ok_pong = wing::parse_ws_frame_header(pong_reply[..]);
        sub.assert_true(ok_pong, "Parsed auto-pong frame header");
        sub.assert_eq(pong_hdr.opcode, wing::WS_OPCODE_PONG, "Opcode in auto-reply is PONG");
        sub.assert_eq(pong_hdr.payload_len, 0, "Pong payload length is 0 bytes");
    };
}

// ----------------------------------------------------------------------------
// 6. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages
// ----------------------------------------------------------------------------
fn test_diagnostic_control_character_sanitization(t: core::T&) {
    t.run("Control characters in untrusted tokens MUST be escaped for safe logging") { sub =>
        // CVE-2026-42507 & Go #79346:
        // Untrusted header tokens containing CRLF or control bytes (< 0x20, > 0x7E)
        // must be escaped to prevent log injection and HTTP response splitting.
        var out_clean: u8[..128] = [];
        wing::escape_diagnostic_control_chars("malformed\r\nInjected-Header: evil", out_clean);

        // Result must NOT contain raw \r or \n
        var has_raw_cr = false;
        var has_raw_lf = false;
        for b in out_clean {
            if b == '\r' { has_raw_cr = true; }
            if b == '\n' { has_raw_lf = true; }
        }
        sub.assert_false(has_raw_cr, "Sanitized string MUST NOT contain raw CR");
        sub.assert_false(has_raw_lf, "Sanitized string MUST NOT contain raw LF");
        sub.assert_bytes_eq(out_clean[..], "malformed\\r\\nInjected-Header: evil", "CRLF correctly escaped to \\r\\n");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense
// ----------------------------------------------------------------------------
fn test_informational_1xx_response_limit(t: core::T&) {
    t.run("Consecutive 1xx responses exceeding limit MUST be rejected") { sub =>
        // RFC 9110 Section 15.2 & Go #65035:
        // Bound consecutive 1xx informational responses (default limit: 5) to prevent infinite loops.
        sub.assert_true(wing::validate_informational_response_count(1, 5), "1st 1xx response is valid");
        sub.assert_true(wing::validate_informational_response_count(5, 5), "5th 1xx response is valid (at limit)");
        sub.assert_false(wing::validate_informational_response_count(6, 5), "6th 1xx response MUST be rejected (> limit)");
        sub.assert_false(wing::validate_informational_response_count(100, 5), "100th 1xx response MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 8. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = "*" ONLY for OPTIONS
// ----------------------------------------------------------------------------
fn test_h2_asterisk_path_only_for_options(t: core::T&) {
    t.run("Asterisk-form :path '*' is valid for OPTIONS method") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "OPTIONS");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method OPTIONS accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "OPTIONS", .. });

        let ok_path = internal::validate_header_ordering_and_rules(headers, ":path", "*");
        sub.assert_eq(ok_path, internal::ERR_NO_ERROR, ":path '*' accepted for OPTIONS");
    };

    t.run("Asterisk-form :path '*' on GET method MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        let err_path = internal::validate_header_ordering_and_rules(headers, ":path", "*");
        sub.assert_eq(err_path, internal::ERR_PROTOCOL_ERROR, "GET with :path '*' MUST be rejected with PROTOCOL_ERROR (RFC 9113 §8.3.1)");
    };
}

// ----------------------------------------------------------------------------
// 9. RFC 9113 §8.3: Request and Response Pseudo-Header Segregation
// ----------------------------------------------------------------------------
fn test_h2_pseudo_header_request_response_segregation(t: core::T&) {
    t.run("Response pseudo-header :status in Request header block MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        let err_status = internal::validate_header_ordering_and_rules(headers, ":status", "200");
        sub.assert_eq(err_status, internal::ERR_PROTOCOL_ERROR, ":status in request header block MUST return PROTOCOL_ERROR (RFC 9113 §8.3)");
    };

    t.run("Request pseudo-header :method in Response header block MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_status = internal::validate_header_ordering_and_rules(headers, ":status", "200");
        sub.assert_eq(ok_status, internal::ERR_NO_ERROR, ":status 200 accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":status", value: "200", .. });

        let err_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(err_meth, internal::ERR_PROTOCOL_ERROR, ":method in response header block MUST return PROTOCOL_ERROR (RFC 9113 §8.3)");
    };
}

// ----------------------------------------------------------------------------
// 10. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicates
// ----------------------------------------------------------------------------
fn test_h2_authority_host_consistency_and_duplicates(t: core::T&) {
    t.run("Matching :authority and Host headers are accepted") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_auth = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com");
        sub.assert_eq(ok_auth, internal::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":authority", value: "example.com", .. });

        let ok_host = internal::validate_header_ordering_and_rules(headers, "host", "example.com");
        sub.assert_eq(ok_host, internal::ERR_NO_ERROR, "Matching Host header accepted");
    };

    t.run("Conflicting :authority and Host headers MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_auth = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com");
        sub.assert_eq(ok_auth, internal::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":authority", value: "example.com", .. });

        let err_host = internal::validate_header_ordering_and_rules(headers, "host", "attacker.com");
        sub.assert_eq(err_host, internal::ERR_PROTOCOL_ERROR, "Conflicting Host 'attacker.com' MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)");
    };

    t.run("Multiple Host headers in HTTP/2 MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.2.1)") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_host1 = internal::validate_header_ordering_and_rules(headers, "host", "example.com");
        sub.assert_eq(ok_host1, internal::ERR_NO_ERROR, "First Host accepted");
        headers.fields.push(internal::DecodedH2Header { name: "host", value: "example.com", .. });

        let err_host2 = internal::validate_header_ordering_and_rules(headers, "host", "example.com");
        sub.assert_eq(err_host2, internal::ERR_PROTOCOL_ERROR, "Duplicate Host header MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.2.1)");
    };
}

// ----------------------------------------------------------------------------
// 11. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys
// ----------------------------------------------------------------------------
fn test_h2c_vs_https_connection_pool_isolation(t: core::T&) {
    t.run("Connection pool key for H2c vs Https to same host:port MUST NOT match") { sub =>
        let dummy_proxy = wing::ProxyChain { .. };
        let dummy_part = wing::NetworkAnonymizationKey { .. };
        let dummy_policy = wing::TlsAndDnsPolicy { .. };

        let h2c_key = wing::new_pool_key(
            wing::PoolScheme.H2c,
            "api.internal",
            80,
            dummy_proxy,
            dummy_part,
            dummy_policy,
        );

        let https_key = wing::new_pool_key(
            wing::PoolScheme.Https,
            "api.internal",
            80,
            dummy_proxy,
            dummy_part,
            dummy_policy,
        );

        sub.assert_false(wing::pool_key_equals(h2c_key, https_key), "H2c and Https pool keys MUST NOT be equal");
        sub.assert_ne(wing::pool_key_hash(h2c_key), wing::pool_key_hash(https_key), "H2c and Https pool keys MUST produce different hashes");
    };
}

// ----------------------------------------------------------------------------
// 12. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection
// ----------------------------------------------------------------------------
fn test_h3_duplicate_control_stream_rejection(t: core::T&) {
    t.run("Second H3_STREAM_CONTROL stream MUST be rejected with H3_ERR_STREAM_CREATION (0x0103)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        // First control stream: Stream ID 3 (unidirectional), Type 0x00 (H3_STREAM_CONTROL)
        var ctrl1_wire: u8[>..] = [];
        internal::quic_encode_varint(ctrl1_wire, internal::H3_STREAM_CONTROL);
        let err1 = conn.handle_stream_data(3, false, ctrl1_wire[..], false);
        sub.assert_eq(err1, internal::H3_ERR_NO_ERROR, "First control stream accepted");
        sub.assert_true(conn.peer_control_opened, "Peer control opened flag set");

        // Second control stream: Stream ID 7 (unidirectional), Type 0x00
        var ctrl2_wire: u8[>..] = [];
        internal::quic_encode_varint(ctrl2_wire, internal::H3_STREAM_CONTROL);
        let err2 = conn.handle_stream_data(7, false, ctrl2_wire[..], false);
        sub.assert_eq(err2, internal::H3_ERR_STREAM_CREATION, "Duplicate control stream MUST return H3_ERR_STREAM_CREATION (0x0103)");
        sub.assert_eq(conn.state, internal::H3ConnState.Closed, "Connection state transitioned to Closed");
    };
}

// ----------------------------------------------------------------------------
// 13. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon
// ----------------------------------------------------------------------------
fn test_chunked_bws_before_semicolon(t: core::T&) {
    t.run("Chunk extension with space before semicolon parses cleanly (RFC 9112 §7.1.1)") { sub =>
        let wire = "5 ; ext=val\r\nhello\r\n0\r\n\r\n";
        var body: u8[>..] = [];
        let err = wing::decode_chunked_body(wire, body);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Chunk extension with BWS before ';' decoded successfully");
        sub.assert_bytes_eq(body[..], "hello", "Decoded chunk data matches expected payload");
    };

    t.run("Chunk extension with tab before semicolon parses cleanly (RFC 9112 §7.1.1)") { sub =>
        let wire = "4\t; ext=token\r\nwing\r\n0\r\n\r\n";
        var body: u8[>..] = [];
        let err = wing::decode_chunked_body(wire, body);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Chunk extension with HTAB before ';' decoded successfully");
        sub.assert_bytes_eq(body[..], "wing", "Decoded chunk data matches expected payload");
    };
}

// --- Component: regress_issues_batch08 ---
// Phase 8 RED test suite based on .gemini issue trackers and RFC specifications.
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
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant
// ----------------------------------------------------------------------------
fn test_h2_goaway_last_stream_id_peer_role(t: core::T&) {
    t.run("Client GOAWAY with odd stream ID sent to Server MUST be rejected with PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 6.8 & Go #80759:
        // "Since streams initiated by a client have odd stream identifiers and streams initiated
        // by a server have even stream identifiers, the Last-Stream-ID sent by a client MUST be
        // an even stream identifier or zero (streams initiated by the peer)."
        // Client sent stream 1 or 3 -> invalid!
        let valid_client_0 = internal::validate_goaway_last_stream_id(0, true);
        sub.assert_true(valid_client_0, "Client GOAWAY with last_stream_id=0 is valid");

        let valid_client_even = internal::validate_goaway_last_stream_id(2, true);
        sub.assert_true(valid_client_even, "Client GOAWAY with last_stream_id=2 (server stream) is valid");

        let invalid_client_odd1 = internal::validate_goaway_last_stream_id(1, true);
        sub.assert_false(invalid_client_odd1, "Client GOAWAY with last_stream_id=1 MUST be rejected (Go #80759)");

        let invalid_client_odd3 = internal::validate_goaway_last_stream_id(3, true);
        sub.assert_false(invalid_client_odd3, "Client GOAWAY with last_stream_id=3 MUST be rejected (Go #80759)");
    };

    t.run("Server GOAWAY with even stream ID > 0 sent to Client MUST be rejected with PROTOCOL_ERROR") { sub =>
        // Server sent stream 2 or 4 -> invalid! Server can only acknowledge client streams (odd) or 0.
        let valid_server_0 = internal::validate_goaway_last_stream_id(0, false);
        sub.assert_true(valid_server_0, "Server GOAWAY with last_stream_id=0 is valid");

        let valid_server_odd = internal::validate_goaway_last_stream_id(1, false);
        sub.assert_true(valid_server_odd, "Server GOAWAY with last_stream_id=1 (client stream) is valid");

        let valid_server_max = internal::validate_goaway_last_stream_id(0x7FFFFFFF, false);
        sub.assert_true(valid_server_max, "Server GOAWAY with 2^31-1 (graceful shutdown) is valid");

        let invalid_server_even2 = internal::validate_goaway_last_stream_id(2, false);
        sub.assert_false(invalid_server_even2, "Server GOAWAY with even stream 2 MUST be rejected (RFC 9113 §6.8)");

        let invalid_server_even4 = internal::validate_goaway_last_stream_id(4, false);
        sub.assert_false(invalid_server_even4, "Server GOAWAY with even stream 4 MUST be rejected (RFC 9113 §6.8)");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9113 §6.8 & Go #82365: HTTP/2 Stream Ingestion Blocked After GOAWAY
// ----------------------------------------------------------------------------
fn test_h2_stream_blocked_after_goaway(t: core::T&) {
    t.run("New stream headers frame on stream > last_stream_id after GOAWAY MUST return ERR_REFUSED_STREAM") { sub =>
        // RFC 9113 Section 6.8 & Go #82365:
        // After receiving a GOAWAY frame with Last-Stream-ID = N, any new stream with ID > N
        // must be rejected.
        var conn = internal::new_h2_connection(0, 8192, false);
        let ok_ga = internal::apply_goaway(conn, 3, internal::ERR_NO_ERROR);
        sub.assert_eq(ok_ga, internal::ERR_NO_ERROR, "apply_goaway accepted");
        sub.assert_true(conn.goaway_received, "goaway_received flag is set");
        sub.assert_eq(conn.goaway_last_stream_id, 3, "goaway_last_stream_id is 3");

        // Attempting to open stream 5 (> 3) after GOAWAY must be refused
        let hdr_st5 = internal::FrameHeader {
            length:     10,
            frame_type: internal::FRAME_HEADERS,
            flags:      internal::FLAG_END_HEADERS,
            stream_id:  5,
        };
        let res_st5 = internal::handle_h2_headers_frame_header(conn, hdr_st5, 0);
        sub.assert_eq(res_st5, internal::ERR_REFUSED_STREAM, "Stream 5 > last_stream_id 3 MUST return REFUSED_STREAM");

        // Stream 1 (<= 3) was processed before GOAWAY, so it is not rejected as refused
        let hdr_st1 = internal::FrameHeader {
            length:     10,
            frame_type: internal::FRAME_HEADERS,
            flags:      internal::FLAG_END_HEADERS,
            stream_id:  1,
        };
        let res_st1 = internal::handle_h2_headers_frame_header(conn, hdr_st1, 0);
        sub.assert_eq(res_st1, internal::ERR_NO_ERROR, "Stream 1 <= last_stream_id 3 is accepted");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header Character Validation
// ----------------------------------------------------------------------------
fn test_h2_path_character_validation(t: core::T&) {
    t.run("Path containing unescaped angle brackets (<>) MUST return ERR_PROTOCOL_ERROR (Go #77843)") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        // Unescaped '>' is forbidden in RFC 3986 pchar and query
        let err_gt = internal::validate_header_ordering_and_rules(headers, ":path", "/api/search?q=test>123");
        sub.assert_eq(err_gt, internal::ERR_PROTOCOL_ERROR, "Path with raw '>' MUST return ERR_PROTOCOL_ERROR (Go #77843)");

        // Unescaped '<' is forbidden
        let err_lt = internal::validate_header_ordering_and_rules(headers, ":path", "/api/search<test");
        sub.assert_eq(err_lt, internal::ERR_PROTOCOL_ERROR, "Path with raw '<' MUST return ERR_PROTOCOL_ERROR (Go #77843)");

        // Space inside path is forbidden
        let err_sp = internal::validate_header_ordering_and_rules(headers, ":path", "/api/my test");
        sub.assert_eq(err_sp, internal::ERR_PROTOCOL_ERROR, "Path with interior space MUST return ERR_PROTOCOL_ERROR");

        // Properly percent-encoded path is valid
        let ok_encoded = internal::validate_header_ordering_and_rules(headers, ":path", "/api/search?q=test%3E123");
        sub.assert_eq(ok_encoded, internal::ERR_NO_ERROR, "Percent-encoded path '/api/search?q=test%3E123' is valid");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers
// ----------------------------------------------------------------------------
fn test_h2_trailer_forbidden_pseudo_headers(t: core::T&) {
    t.run("Pseudo-headers in HTTP/2 trailer block MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3)") { sub =>
        // RFC 9113 Section 8.3:
        // "Pseudo-header fields MUST NOT appear in trailer sections."
        var trailers = internal::DecodedH2HeaderList { is_trailer: true, .. };

        let err_status = internal::validate_header_ordering_and_rules(trailers, ":status", "200");
        sub.assert_eq(err_status, internal::ERR_PROTOCOL_ERROR, "Pseudo-header :status in trailers MUST return PROTOCOL_ERROR");

        let err_path = internal::validate_header_ordering_and_rules(trailers, ":path", "/index");
        sub.assert_eq(err_path, internal::ERR_PROTOCOL_ERROR, "Pseudo-header :path in trailers MUST return PROTOCOL_ERROR");

        // Regular trailer field is valid
        let ok_trailer = internal::validate_header_ordering_and_rules(trailers, "grpc-status", "0");
        sub.assert_eq(ok_trailer, internal::ERR_NO_ERROR, "Regular trailer field 'grpc-status' is valid");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 6455 §4.2.1: WebSocket Upgrade Handshake Missing Host Header Rejection
// ----------------------------------------------------------------------------
fn test_ws_handshake_missing_host_rejection(t: core::T&) {
    t.run("WebSocket Upgrade handshake without Host header MUST be rejected with HTTP 400") { sub =>
        // RFC 6455 Section 4.2.1 item 2:
        // "The request MUST contain a |Host| header field."
        // "If the handshake lacks a Host header, the server MUST respond with 400 Bad Request."
        var req = wing::new_request("GET", "/ws");
        wing::set_header(req, "Upgrade", "websocket");
        wing::set_header(req, "Connection", "Upgrade");
        wing::set_header(req, "Sec-WebSocket-Version", "13");
        wing::set_header(req, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        // Omit Host header!

        var resp = wing::Response { .. };
        let _, ok = wing::ws_upgrade_request(req, resp);
        sub.assert_false(ok, "Upgrade handshake MUST fail when Host header is missing (RFC 6455 §4.2.1)");
        sub.assert_eq(resp.status_code, 400, "Response status code MUST be 400 Bad Request");

        sub.assert_false(wing::is_websocket_upgrade_request(req), "is_websocket_upgrade_request MUST return false without Host");

        // With valid Host header, handshake succeeds
        wing::set_header(req, "Host", "example.com");
        var resp_ok = wing::Response { .. };
        let _, ok_with_host = wing::ws_upgrade_request(req, resp_ok);
        sub.assert_true(ok_with_host, "Upgrade handshake succeeds with Host header present");
        sub.assert_eq(resp_ok.status_code, 101, "Response status code is 101 Switching Protocols");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 6455 §4.2.2: WebSocket Subprotocol Agreement Verification
// ----------------------------------------------------------------------------
fn test_ws_subprotocol_agreement_verification(t: core::T&) {
    t.run("Server selecting subprotocol NOT offered by client MUST NOT negotiate it (RFC 6455 §4.2.2)") { sub =>
        // RFC 6455 Section 4.2.2 item 5:
        // "If the server does include a |Sec-WebSocket-Protocol| header field in its response,
        // the value of that field MUST be one of the subprotocols requested by the client."
        var req = wing::new_request("GET", "/ws");
        wing::set_header(req, "Host", "example.com");
        wing::set_header(req, "Upgrade", "websocket");
        wing::set_header(req, "Connection", "Upgrade");
        wing::set_header(req, "Sec-WebSocket-Version", "13");
        wing::set_header(req, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        wing::set_header(req, "Sec-WebSocket-Protocol", "chat, superchat");

        // Server attempts to negotiate "unsupported_protocol" not offered by client
        var resp_unmatched = wing::Response { .. };
        let sess_unmatched, ok1 = wing::ws_upgrade_request(req, resp_unmatched, "unsupported_protocol");
        sub.assert_true(ok1, "Handshake succeeds");
        sub.assert_eq(sess_unmatched.subprotocol.len, 0, "Unmatched subprotocol MUST NOT be accepted in session");
        sub.assert_false(wing::has_header(resp_unmatched, "Sec-WebSocket-Protocol"), "Sec-WebSocket-Protocol header MUST NOT be sent for unoffered protocol");

        // Server selects "chat" which WAS offered by client
        var resp_matched = wing::Response { .. };
        let sess_matched, ok2 = wing::ws_upgrade_request(req, resp_matched, "chat");
        sub.assert_true(ok2, "Handshake succeeds");
        sub.assert_bytes_eq(sess_matched.subprotocol[..], "chat", "Matched subprotocol 'chat' is negotiated");
        sub.assert_bytes_eq(wing::header(resp_matched, "Sec-WebSocket-Protocol"), "chat", "Sec-WebSocket-Protocol header contains 'chat'");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection
// ----------------------------------------------------------------------------
fn test_relative_url_double_slash_path_protection(t: core::T&) {
    t.run("Relative path starting with encoded slashes MUST NOT be converted to authority (Go #81292)") { sub =>
        // Go #81292 / RFC 3986 Section 4.2:
        // Percent-encoded slashes in relative paths must not promote a path to a host.
        let base = core::new_url("https://example.com/api/");
        let parsed = core::new_url("/relative/path", base);
        let smuggled = core::new_url("/%2fevil.com/path", base);
        sub.assert_true(smuggled.valid, "Parsed percent-encoded slash relative URL is valid");
        sub.assert_bytes_eq(core::hostname(smuggled), "example.com", "Hostname MUST remain example.com, not promote evil.com to authority");
        sub.assert_true(parsed.valid, "Parsed relative URL is valid");
        sub.assert_bytes_eq(core::hostname(parsed), "example.com", "Hostname retained as example.com");
        sub.assert_bytes_eq(core::pathname(parsed), "/relative/path", "Pathname matches /relative/path");
    };
}

// --- Component: regress_issues_batch09 ---
// Phase 9 RED test suite based on .gemini issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and security edge cases:
//
// 1. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWebSockets #1949: HTTP/1.1 Host Header Character Validation & Duplicate Rejection
// 2. RFC 9113 §8.3.1 & uWebSockets #1949: HTTP/2 :authority Pseudo-Header Forbidden Characters
// 3. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields
// 4. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants
// 5. RFC 9113 §6.5.2: HTTP/2 Client SETTINGS Frame Rejection of SETTINGS_ENABLE_PUSH != 0
// 6. RFC 3986 §3.2.2 & Go #77578 (CVE-2026-25679) / CVE-2025-47912: URL Bracketed Host Validation
// 7. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Cross-Origin Redirect Sensitive Header Stripping

// ----------------------------------------------------------------------------
// 1. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWebSockets #1949: HTTP/1.1 Host Validation
// ----------------------------------------------------------------------------
fn test_h1_host_header_validation_and_duplicates(t: core::T&) {
    t.run("Host header with path, query, fragment or userinfo MUST be rejected (uWS #1949)") { sub =>
        // RFC 9112 Section 7.2:
        // Host = uri-host [ ":" port ]
        // Must not contain path (/), query (?), fragment (#), or userinfo (@)
        var map1 = wing::HeaderMap { .. };
        let err_path = wing::parse_headers("Host: example.com/path\r\n\r\n", map1);
        sub.assert_false(wing::is_ok(err_path), "Host with path '/' MUST be rejected");

        var map2 = wing::HeaderMap { .. };
        let err_query = wing::parse_headers("Host: example.com?q=1\r\n\r\n", map2);
        sub.assert_false(wing::is_ok(err_query), "Host with query '?' MUST be rejected");

        var map3 = wing::HeaderMap { .. };
        let err_hash = wing::parse_headers("Host: example.com#frag\r\n\r\n", map3);
        sub.assert_false(wing::is_ok(err_hash), "Host with fragment '#' MUST be rejected");

        var map4 = wing::HeaderMap { .. };
        let err_at = wing::parse_headers("Host: user@example.com\r\n\r\n", map4);
        sub.assert_false(wing::is_ok(err_at), "Host with userinfo '@' MUST be rejected");

        var map_ok = wing::HeaderMap { .. };
        let err_ok = wing::parse_headers("Host: example.com:8080\r\n\r\n", map_ok);
        sub.assert_true(wing::is_ok(err_ok), "Clean Host 'example.com:8080' is valid");
    };

    t.run("Duplicate Host headers in HTTP/1.1 MUST be rejected (RFC 9112 §7.2)") { sub =>
        var map_dup = wing::HeaderMap { .. };
        let err_dup = wing::parse_headers("Host: example.com\r\nHost: evil.com\r\n\r\n", map_dup);
        sub.assert_false(wing::is_ok(err_dup), "Duplicate Host headers MUST be rejected (smuggling protection)");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9113 §8.3.1 & uWebSockets #1949: HTTP/2 :authority Forbidden Characters
// ----------------------------------------------------------------------------
fn test_h2_authority_character_validation(t: core::T&) {
    t.run(":authority with path, query, fragment or userinfo MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, internal::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        let err_path = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com/api");
        sub.assert_eq(err_path, internal::ERR_PROTOCOL_ERROR, ":authority with '/' MUST return ERR_PROTOCOL_ERROR");

        let err_query = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com?foo=1");
        sub.assert_eq(err_query, internal::ERR_PROTOCOL_ERROR, ":authority with '?' MUST return ERR_PROTOCOL_ERROR");

        let err_hash = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com#sec");
        sub.assert_eq(err_hash, internal::ERR_PROTOCOL_ERROR, ":authority with '#' MUST return ERR_PROTOCOL_ERROR");

        let err_user = internal::validate_header_ordering_and_rules(headers, ":authority", "admin@example.com");
        sub.assert_eq(err_user, internal::ERR_PROTOCOL_ERROR, ":authority with '@' MUST return ERR_PROTOCOL_ERROR");

        let ok_auth = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com:443");
        sub.assert_eq(ok_auth, internal::ERR_NO_ERROR, ":authority 'example.com:443' is valid");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields
// ----------------------------------------------------------------------------
fn test_h2_trailer_disallowed_fields(t: core::T&) {
    t.run("Disallowed headers in HTTP/2 trailers MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.1.2)") { sub =>
        var trailers = internal::DecodedH2HeaderList { is_trailer: true, .. };

        let err_cl = internal::validate_header_ordering_and_rules(trailers, "content-length", "100");
        sub.assert_eq(err_cl, internal::ERR_PROTOCOL_ERROR, "content-length in trailers MUST return PROTOCOL_ERROR");

        let err_te = internal::validate_header_ordering_and_rules(trailers, "transfer-encoding", "chunked");
        sub.assert_eq(err_te, internal::ERR_PROTOCOL_ERROR, "transfer-encoding in trailers MUST return PROTOCOL_ERROR");

        let err_host = internal::validate_header_ordering_and_rules(trailers, "host", "evil.com");
        sub.assert_eq(err_host, internal::ERR_PROTOCOL_ERROR, "host in trailers MUST return PROTOCOL_ERROR");

        let err_conn = internal::validate_header_ordering_and_rules(trailers, "connection", "close");
        sub.assert_eq(err_conn, internal::ERR_PROTOCOL_ERROR, "connection in trailers MUST return PROTOCOL_ERROR");

        let err_tr = internal::validate_header_ordering_and_rules(trailers, "trailer", "x-foo");
        sub.assert_eq(err_tr, internal::ERR_PROTOCOL_ERROR, "trailer in trailers MUST return PROTOCOL_ERROR");

        let ok_custom = internal::validate_header_ordering_and_rules(trailers, "x-checksum-sha256", "abc123def");
        sub.assert_eq(ok_custom, internal::ERR_NO_ERROR, "Allowed trailer header 'x-checksum-sha256' is valid");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants
// ----------------------------------------------------------------------------
fn test_h3_pseudo_header_invariants(t: core::T&) {
    t.run("Duplicate :status or pseudo-headers after regular headers MUST be rejected (RFC 9114 §4.3)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Open request stream
        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with duplicate :status
        var qpack_dup: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_dup, ":status", "200");
        internal::encode_qpack_field(qpack_dup, ":status", "500");

        var wire_dup: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_dup, qpack_dup[..]);

        let res_dup = conn.handle_stream_data(s_id, true, wire_dup[..], false);
        sub.assert_eq(res_dup, internal::H3_ERR_GENERAL_PROTOCOL, "Duplicate :status MUST return H3_ERR_GENERAL_PROTOCOL");

        // Test pseudo-header after regular header
        var conn2 = internal::new_h3_client_connection(settings);
        let s_id2, ok_open2 = conn2.open_request_stream();
        sub.assert_true(ok_open2, "Stream opened");

        var qpack_order: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_order, "content-type", "text/plain");
        internal::encode_qpack_field(qpack_order, ":status", "200");

        var wire_order: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_order, qpack_order[..]);

        let res_order = conn2.handle_stream_data(s_id2, true, wire_order[..], false);
        sub.assert_eq(res_order, internal::H3_ERR_GENERAL_PROTOCOL, "Pseudo-header after regular header MUST return H3_ERR_GENERAL_PROTOCOL");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 9113 §6.5.2: HTTP/2 Client Rejection of SETTINGS_ENABLE_PUSH != 0
// ----------------------------------------------------------------------------
fn test_h2_client_settings_enable_push_rejection(t: core::T&) {
    t.run("Client receiving SETTINGS_ENABLE_PUSH != 0 MUST return PROTOCOL_ERROR (RFC 9113 §6.5.2)") { sub =>
        // Server receiving ENABLE_PUSH = 1 from client is VALID
        let ok_server = internal::validate_settings_parameter(internal::SETTING_ENABLE_PUSH, 1, false);
        sub.assert_eq(ok_server, internal::ERR_NO_ERROR, "Server receiving ENABLE_PUSH=1 from client is valid");

        // Client receiving ENABLE_PUSH = 1 from server MUST be rejected
        let err_client = internal::validate_settings_parameter(internal::SETTING_ENABLE_PUSH, 1, true);
        sub.assert_eq(err_client, internal::ERR_PROTOCOL_ERROR, "Client receiving ENABLE_PUSH=1 from server MUST return ERR_PROTOCOL_ERROR");

        // Client receiving ENABLE_PUSH = 0 from server is VALID
        let ok_client0 = internal::validate_settings_parameter(internal::SETTING_ENABLE_PUSH, 0, true);
        sub.assert_eq(ok_client0, internal::ERR_NO_ERROR, "Client receiving ENABLE_PUSH=0 from server is valid");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 3986 §3.2.2 & Go #77578 / CVE-2025-47912: URL Bracketed Host Validation
// ----------------------------------------------------------------------------
fn test_url_bracketed_host_validation(t: core::T&) {
    t.run("IPv4 and non-IP hostnames in brackets MUST be rejected (CVE-2025-47912)") { sub =>
        let u1 = core::new_url("http://[127.0.0.1]/");
        sub.assert_false(u1.valid, "http://[127.0.0.1]/ MUST NOT be accepted as valid URL");

        let u2 = core::new_url("http://[example.com]/");
        sub.assert_false(u2.valid, "http://[example.com]/ MUST NOT be accepted as valid URL");

        let u_valid = core::new_url("http://[::1]/");
        sub.assert_true(u_valid.valid, "http://[::1]/ is a valid IPv6 URL");
    };

    t.run("IPv6 brackets not at start of host MUST be rejected (Go #77578 / CVE-2026-25679)") { sub =>
        let u_bad_pre = core::new_url("http://foo[::1]/");
        sub.assert_false(u_bad_pre.valid, "http://foo[::1]/ MUST be rejected");

        let u_bad_mid = core::new_url("http://example.com[::1]:80/");
        sub.assert_false(u_bad_mid.valid, "http://example.com[::1]:80/ MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Redirect Sensitive Header Stripping
// ----------------------------------------------------------------------------
fn test_redirect_sensitive_header_stripping(t: core::T&) {
    t.run("Proxy-Authorization and Authorization purged on cross-origin redirect (CVE-2025-4673)") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Authorization", "Bearer secret123"));
        headers.push(wing::make_header("Proxy-Authorization", "Basic proxysecret"));
        headers.push(wing::make_header("User-Agent", "GooseWing/1.0"));

        let red_info = wing::RedirectInfo {
            is_cross_origin:     true,
            is_scheme_downgrade: false,
            is_port_changed:     false,
            clear_body:          false,
            ..
        };

        wing::sanitize_headers_on_redirect(headers, red_info, false, false, false, false);

        let has_auth = wing::find_header_index(headers[..], "Authorization") >= 0;
        sub.assert_false(has_auth, "Authorization header MUST be stripped on cross-origin redirect");

        let has_proxy_auth = wing::find_header_index(headers[..], "Proxy-Authorization") >= 0;
        sub.assert_false(has_proxy_auth, "Proxy-Authorization MUST be stripped on cross-origin redirect (CVE-2025-4673)");

        let has_ua = wing::find_header_index(headers[..], "User-Agent") >= 0;
        sub.assert_true(has_ua, "User-Agent header is preserved across redirect");
    };
}

// --- Component: regress_issues_batch10 ---
// Phase 10 RED test suite: Heapless Fixed-Capacity Buffer Safety & RFC Invariants
// Tests capacity truncation smuggling, bounds aborts, and RFC protocol non-conformances:
//
// 1. Path dot-segment desync when segments exceed buffer capacity (core/url/parser.goose)
// 2. URL oversized input & scheme handling without runtime abort (core/url/parser.goose)
// 3. Query parameter smuggling & key truncation false match (core/url/query.goose)
// 4. MediaType parameter truncation smuggling & duplicate boundary (http/mime.goose)
// 5. Multipart oversized Content-Type header on part without abort (http/multipart.goose)
// 6. HPACK literal header with indexed name value > 16B abort (http2/hpack.goose)
// 7. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)
// 8. HTTP/3 unknown pseudo-header (:custom) & CTL character rejection (http3/connection.goose)
// 9. Router path capacity truncation smuggling (server/router.goose)
// 10. Alt-Svc oversized proto/host/endpoint capacity safety (http/altsvc.goose)

// ----------------------------------------------------------------------------
// 1. Path dot-segment desync on segment capacity overflow (core/url/parser.goose)
// ----------------------------------------------------------------------------
fn test_path_dot_segment_capacity_desync(t: core::T&) {
    t.run("Path dot-segment normalization MUST NOT desync when segments exceed 256") { sub =>
        // Construct a URL with 256 's' segments, followed by 'target' and '/..'
        // E.g.: http://example.com/s/s/.../s/target/..
        // Total segments before '..': 257.
        // If segment 257 ('target') is omitted from seg_starts, '/..' pops segment 256 ('s'),
        // leaving 'target' in the path and deleting an innocent earlier segment!
        var raw_url: u8[..2048] = [];
        raw_url.append("http://example.com");
        for i in 256 {
            raw_url.append("/s");
        }
        raw_url.append("/target/..");

        let parsed = core::new_url(raw_url[..]);
        sub.assert_true(parsed.valid, "URL with 257 segments should parse or fail safely");

        let path = core::pathname(parsed);
        // 'target' should have been canceled out by '..'
        let has_target = find(path, "target") >= 0;
        sub.assert_false(has_target, "Path segment 'target' MUST be canceled by '/..' and not leak into normalized path");

        // Count how many '/s' segments remain: must be exactly 256!
        var s_count = 0;
        var cur: i64 = 0;
        while cur < path.len {
            let idx = find(path[cur..], "/s");
            if idx >= 0 {
                s_count++;
                cur += idx + 2;
            } else {
                break;
            }
        }
        sub.assert_eq(s_count, 256, "Exactly 256 '/s' segments must remain; segment 256 MUST NOT be popped by target/..");
    };

    t.run("Fixed-capacity try_push and try_append return false on capacity boundary") { sub =>
        var arr: i32[..4] = [];
        sub.assert_true(arr.try_push(10), "try_push 1 should succeed");
        sub.assert_true(arr.try_push(20), "try_push 2 should succeed");
        sub.assert_true(arr.try_push(30), "try_push 3 should succeed");
        sub.assert_true(arr.try_push(40), "try_push 4 should succeed");
        sub.assert_false(arr.try_push(50), "try_push 5 MUST fail on full buffer");
        sub.assert_eq(arr.len, 4, "arr.len must remain 4 without truncation corruption");

        var str: u8[..6] = [];
        sub.assert_true(str.try_append("abc"), "try_append abc should succeed");
        sub.assert_false(str.try_append("defg"), "try_append defg MUST fail because 3 + 4 > 6");
        sub.assert_eq(str.len, 3, "str.len must remain 3 after failed try_append");
        sub.assert_true(str.try_append("def"), "try_append def should succeed exactly filling capacity");
        sub.assert_eq(str.len, 6, "str.len must be 6");
    };

    t.run("URL path depth exceeding 1024 segments returns UrlParseError.PathTooDeep") { sub =>
        var deep_path: u8[..2048] = [];
        deep_path.append("http://example.com");
        for i in 1025 {
            deep_path.push('/');
        }

        let parsed, err = core::parse_url(deep_path[..]);
        sub.assert_false(parsed.valid, "URL with > 1024 segments must be invalid");
        sub.assert_true(err == core::UrlParseError.PathTooDeep, "Error code MUST be UrlParseError.PathTooDeep");
    };
}

// ----------------------------------------------------------------------------
// 2. URL oversized input & scheme handling without runtime abort (core/url/parser.goose)
// ----------------------------------------------------------------------------
fn test_url_oversized_input_no_abort(t: core::T&) {
    t.run("URL with scheme > 64 bytes MUST be rejected gracefully without abort") { sub =>
        var long_scheme: u8[..128] = [];
        for i in 70 { long_scheme.push('a'); }
        long_scheme.append("://example.com/");

        let parsed = core::new_url(long_scheme[..]);
        sub.assert_false(parsed.valid, "Scheme > 64 bytes MUST be marked invalid without abort");
    };

    t.run("URL input > 2048 bytes MUST be rejected gracefully without abort") { sub =>
        var giant_url: u8[>..] = [];
        giant_url.append("http://example.com/");
        for i in 2100 { giant_url.push('x'); }

        let parsed = core::new_url(giant_url[..]);
        sub.assert_false(parsed.valid, "URL input > 2048 bytes MUST be rejected without bounds abort");
    };
}

// ----------------------------------------------------------------------------
// 3. Query parameter smuggling & key truncation false match (core/url/query.goose)
// ----------------------------------------------------------------------------
fn test_query_parameter_smuggling_and_truncation(t: core::T&) {
    t.run("Fast query param lookup MUST NOT falsely match when key exceeds 64 bytes") { sub =>
        // Construct query: ?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_evil=1
        // (64 'a's followed by '_evil')
        var raw_query: u8[..256] = [];
        raw_query.append("?");
        for i in 64 { raw_query.push('a'); }
        raw_query.append("_evil=1");

        // Search for 64 'a's: it MUST NOT match!
        var search_key: u8[..64] = [];
        for i in 64 { search_key.push('a'); }

        var out_val: u8[..64] = [];
        let found, _ = core::get_query_param_fast(raw_query[..], search_key[..], out_val);
        sub.assert_false(found, "Fast query param lookup MUST NOT falsely match truncated 64-byte key");
    };

    t.run("Query param parser MUST NOT silently drop parameter 129 (smuggling)") { sub =>
        // Construct query with 128 benign params followed by '&admin=true'
        var raw_query: u8[>..] = [];
        for i in 128 {
            if i > 0 { raw_query.push('&'); }
            raw_query.append("p");
            core::format_u64_dec(i as u64, raw_query);
            raw_query.append("=val");
        }
        raw_query.append("&admin=true");

        // Fixed-capacity protocol decoders must treat buffer overflow as an explicit error
        let count_valid = core::validate_query_param_count(raw_query[..]);
        sub.assert_false(count_valid, "validate_query_param_count MUST reject query when parameters exceed capacity 128");

        let list = core::parse_query_params(raw_query[..]);
        sub.assert_true(list.overflow, "parse_query_params MUST flag overflow when parameters exceed capacity 128");
    };
}

// ----------------------------------------------------------------------------
// 4. MediaType parameter truncation smuggling & duplicate boundary (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_mime_parameter_truncation_and_boundary(t: core::T&) {
    t.run("MediaType parameter count > 16 MUST fail parsing (no silent drop)") { sub =>
        // 16 dummy parameters followed by '; boundary=evil_boundary'
        var raw_mt: u8[..1024] = [];
        raw_mt.append("multipart/form-data");
        for i in 16 {
            raw_mt.append("; p");
            core::format_u64_dec(i as u64, raw_mt);
            raw_mt.append("=val");
        }
        raw_mt.append("; boundary=evil_boundary");

        let mt, ok = wing::parse_media_type(raw_mt[..]);
        sub.assert_false(ok, "MediaType with > 16 parameters MUST fail parsing instead of silently dropping boundary");
    };

    t.run("Duplicate boundary parameter MUST be rejected (RFC 2046 / Go #82343)") { sub =>
        let raw = "multipart/form-data; boundary=first; boundary=second";
        let mt, ok = wing::parse_media_type(raw);
        sub.assert_false(ok, "Duplicate boundary parameter MUST be rejected");
    };

    t.run("MediaType parameter value > 256 bytes MUST fail safely without abort") { sub =>
        var raw_long_val: u8[..512] = [];
        raw_long_val.append("text/plain; charset=\"");
        for i in 300 { raw_long_val.push('u'); }
        raw_long_val.append("\"");

        let mt, ok = wing::parse_media_type(raw_long_val[..]);
        sub.assert_false(ok, "Parameter value > 256 bytes MUST fail parsing safely without abort");
    };
}

// ----------------------------------------------------------------------------
// 5. Multipart oversized Content-Type header on part without abort (http/multipart.goose)
// ----------------------------------------------------------------------------
fn test_multipart_oversized_content_type_no_abort(t: core::T&) {
    t.run("Multipart part with Content-Type > 64 bytes MUST NOT abort") { sub =>
        var body: u8[..1024] = [];
        body.append("--myboundary\r\n");
        body.append("Content-Disposition: form-data; name=\"upload\"; filename=\"test.docx\"\r\n");
        // 71-byte Content-Type (exceeds part.content_type: u8[..64] capacity)
        body.append("Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n");
        body.append("payload content\r\n");
        body.append("--myboundary--\r\n");

        let msg, err = wing::parse_multipart(body[..], "myboundary");
        sub.assert_true(wing::is_ok(err), "Part with long Content-Type header MUST parse without bounds abort");
        sub.assert_eq(msg.parts.len, 1, "Parsed 1 part");
        sub.assert_true(msg.parts[0].content_type.len > 0, "Part content_type must be captured");
    };
}

// ----------------------------------------------------------------------------
// 6. HPACK literal header with indexed name value > 16B abort (http2/hpack.goose)
// ----------------------------------------------------------------------------
fn test_hpack_literal_indexed_name_dynamic_value_overflow(t: core::T&) {
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

        var out_headers = internal::DecodedH2HeaderList { .. };
        let err_code = internal::decode_hpack_header_block(dt, wire[..], out_headers);
        sub.assert_eq(err_code, internal::ERR_NO_ERROR, "Literal header with indexed name from dynamic table MUST decode without bounds abort");
        sub.assert_eq(out_headers.fields.len, 1, "Decoded 1 header");
        sub.assert_eq(out_headers.fields[0].name[..], "custom-header", "Header name matches dynamic table entry");
        sub.assert_eq(out_headers.fields[0].value[..], "newval", "Header value matches literal value");
    };
}

// ----------------------------------------------------------------------------
// 7. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)
// ----------------------------------------------------------------------------
fn test_h2_authority_whitespace_rejection(t: core::T&) {
    t.run(":authority with interior space MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        let code = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com :80");
        sub.assert_eq(code, internal::ERR_PROTOCOL_ERROR, ":authority with space MUST be rejected with ERR_PROTOCOL_ERROR");
    };

    t.run(":authority with comma MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = internal::DecodedH2HeaderList { .. };
        let ok_meth = internal::validate_header_ordering_and_rules(headers, ":method", "GET");
        headers.fields.push(internal::DecodedH2Header { name: ":method", value: "GET", .. });

        let code = internal::validate_header_ordering_and_rules(headers, ":authority", "example.com,evil.com");
        sub.assert_eq(code, internal::ERR_PROTOCOL_ERROR, ":authority with comma MUST be rejected with ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 8. HTTP/3 unknown pseudo-header (:custom) & CTL character rejection (http3/connection.goose)
// ----------------------------------------------------------------------------
fn test_h3_pseudo_header_unknown_and_ctl(t: core::T&) {
    t.run("HTTP/3 request with unknown pseudo-header :custom MUST return error") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with unknown pseudo-header :custom
        var qpack_buf: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_buf, ":method", "GET");
        internal::encode_qpack_field(qpack_buf, ":scheme", "https");
        internal::encode_qpack_field(qpack_buf, ":path", "/");
        internal::encode_qpack_field(qpack_buf, ":custom", "invalid");

        var wire_buf: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_buf, qpack_buf[..]);

        let res = conn.handle_stream_data(s_id, true, wire_buf[..], false);
        sub.assert_true(res != internal::H3_ERR_NO_ERROR, "HTTP/3 unknown pseudo-header :custom MUST be rejected with error (RFC 9114 §4.3)");
    };

    t.run("HTTP/3 header with CTL character MUST return error") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with CTL char 0x01 in header value
        var qpack_buf: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_buf, ":method", "GET");
        internal::encode_qpack_field(qpack_buf, ":scheme", "https");
        internal::encode_qpack_field(qpack_buf, ":path", "/");
        internal::encode_qpack_field(qpack_buf, "custom", "bad\x01value");

        var wire_buf: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_buf, qpack_buf[..]);

        let res = conn.handle_stream_data(s_id, true, wire_buf[..], false);
        sub.assert_true(res != internal::H3_ERR_NO_ERROR, "HTTP/3 header value with CTL MUST be rejected with error (RFC 9114 §4.2)");
    };
}

// ----------------------------------------------------------------------------
// 9. Router path capacity truncation smuggling (server/router.goose)
// ----------------------------------------------------------------------------
fn test_router_path_capacity_truncation_smuggling(t: core::T&) {
    t.run("Router MUST NOT truncate oversized path to match parent route") { sub =>
        var router = wing::new_radix_router();
        wing::add_route(router, "GET", "/admin", 1);

        // Path is /admin/ + 520 'x's (exceeds 512 bytes)
        var long_path: u8[..600] = [];
        long_path.append("/admin/");
        for i in 520 { long_path.push('x'); }

        var params = wing::ZeroAllocParams { .. };
        let match_res = wing::match_route(router, "GET", long_path[..], params);
        let is_found = match match_res {
            Found _ => true,
            _ => false,
        };
        sub.assert_false(is_found, "Oversized non-matching subpath MUST NOT be truncated to match /admin");
    };
}

// ----------------------------------------------------------------------------
// 10. Alt-Svc oversized proto/host/endpoint capacity safety (http/altsvc.goose)
// ----------------------------------------------------------------------------
fn test_altsvc_oversized_capacity_safety(t: core::T&) {
    t.run("Alt-Svc with > 4 endpoints MUST NOT abort on fixed array overflow") { sub =>
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        // Header with 5 endpoints
        let raw = "h3=\":443\", h2=\":443\", h3-29=\":443\", h3-Q050=\":443\", h3-Q046=\":443\"";
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);
        sub.assert_true(ok, "Alt-Svc with 5 endpoints parsed without aborting");
        sub.assert_eq(endpoints.len, 4, "Capacity clamped cleanly at 4 without crash");
    };

    t.run("Alt-Svc with proto > 16 bytes MUST NOT abort") { sub =>
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        let raw = "superlongprotonamethatexceeds16bytes=\":443\"";
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);
        sub.assert_true(ok, "Alt-Svc with long proto parsed without aborting");
    };
}

fn main() {
    var runner = core::new_runner("Issue Regression Suite Batch 2 (Phases 6-10)", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 9113 §8.2.1: HTTP/2 Field Value CTL Characters", test_h2_field_value_ctl_rejection);
    core::run_case(runner, "2. RFC 9113 §8.3: Undefined Pseudo-Headers Rejection", test_h2_undefined_pseudo_header_rejection);
    core::run_case(runner, "3. RFC 9114 §4.2: QPACK Uppercase Literal Field Names", test_qpack_uppercase_literal_field_name_rejection);
    core::run_case(runner, "4. RFC 9113 §6.6: Frame Rules for PUSH_PROMISE", test_h2_push_promise_frame_rules);
    core::run_case(runner, "5. RFC 9112 §7.1: Chunked FSM Bare LF Rejection", test_chunked_fsm_bare_lf_rejection);
    core::run_case(runner, "6. RFC 9112 §7.1.1: Chunked FSM BWS Before Semicolon", test_chunked_fsm_bws_preceding_semicolon);
    core::run_case(runner, "7. RFC 9110 §13.2.2: Cache-Control Field Names Length Safety", test_cache_control_field_names_overflow_protection);
    core::run_case(runner, "8. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Stream ID Invariant", test_h2_goaway_stream_id_zero);
    core::run_case(runner, "9. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Ignored", test_cookie_relative_path_ignored);
    core::run_case(runner, "10. RFC 9110 §13.2.1: Cache-Control max-age Arithmetic Overflow Clamping", test_cache_control_max_age_overflow_clamping);
    core::run_case(runner, "11. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present", test_h2_connect_scheme_path_rejection);
    core::run_case(runner, "12. RFC 6455 §5.5 & Go #7825: WebSocket Empty Payload Ping / Pong Roundtrip", test_ws_empty_payload_ping_pong);
    core::run_case(runner, "13. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages", test_diagnostic_control_character_sanitization);
    core::run_case(runner, "14. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense", test_informational_1xx_response_limit);
    core::run_case(runner, "15. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = '*' ONLY for OPTIONS", test_h2_asterisk_path_only_for_options);
    core::run_case(runner, "16. RFC 9113 §8.3: Request and Response Pseudo-Header Segregation", test_h2_pseudo_header_request_response_segregation);
    core::run_case(runner, "17. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicates", test_h2_authority_host_consistency_and_duplicates);
    core::run_case(runner, "18. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys", test_h2c_vs_https_connection_pool_isolation);
    core::run_case(runner, "19. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection", test_h3_duplicate_control_stream_rejection);
    core::run_case(runner, "20. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon", test_chunked_bws_before_semicolon);
    core::run_case(runner, "21. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant", test_h2_goaway_last_stream_id_peer_role);
    core::run_case(runner, "22. RFC 9113 §6.8 & Go #82365: HTTP/2 Inbound Stream Rejection After GOAWAY", test_h2_stream_blocked_after_goaway);
    core::run_case(runner, "23. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header Character Validation", test_h2_path_character_validation);
    core::run_case(runner, "24. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers", test_h2_trailer_forbidden_pseudo_headers);
    core::run_case(runner, "25. RFC 6455 §4.2.1: WebSocket Upgrade Handshake Missing Host Header Rejection", test_ws_handshake_missing_host_rejection);
    core::run_case(runner, "26. RFC 6455 §4.2.2: WebSocket Subprotocol Agreement Verification", test_ws_subprotocol_agreement_verification);
    core::run_case(runner, "27. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection", test_relative_url_double_slash_path_protection);
    core::run_case(runner, "28. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWS #1949: HTTP/1.1 Host Header Validation", test_h1_host_header_validation_and_duplicates);
    core::run_case(runner, "29. RFC 9113 §8.3.1 & uWS #1949: HTTP/2 :authority Forbidden Characters", test_h2_authority_character_validation);
    core::run_case(runner, "30. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields", test_h2_trailer_disallowed_fields);
    core::run_case(runner, "31. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants", test_h3_pseudo_header_invariants);
    core::run_case(runner, "32. RFC 9113 §6.5.2: HTTP/2 Client SETTINGS Frame Rejection of SETTINGS_ENABLE_PUSH != 0", test_h2_client_settings_enable_push_rejection);
    core::run_case(runner, "33. RFC 3986 §3.2.2 & Go #77578 / CVE-2025-47912: URL Bracketed Host Validation", test_url_bracketed_host_validation);
    core::run_case(runner, "34. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Redirect Sensitive Header Stripping", test_redirect_sensitive_header_stripping);
    core::run_case(runner, "35. Path dot-segment capacity desync (core/url/parser.goose)", test_path_dot_segment_capacity_desync);
    core::run_case(runner, "36. URL oversized input handling without abort (core/url/parser.goose)", test_url_oversized_input_no_abort);
    core::run_case(runner, "37. Query parameter smuggling & key truncation (core/url/query.goose)", test_query_parameter_smuggling_and_truncation);
    core::run_case(runner, "38. MediaType parameter truncation & duplicate boundary (http/mime.goose)", test_mime_parameter_truncation_and_boundary);
    core::run_case(runner, "39. Multipart oversized Content-Type header on part (http/multipart.goose)", test_multipart_oversized_content_type_no_abort);
    core::run_case(runner, "40. HPACK literal header indexed name dynamic value overflow (http2/hpack.goose)", test_hpack_literal_indexed_name_dynamic_value_overflow);
    core::run_case(runner, "41. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)", test_h2_authority_whitespace_rejection);
    core::run_case(runner, "42. HTTP/3 unknown pseudo-header & CTL character rejection (http3/connection.goose)", test_h3_pseudo_header_unknown_and_ctl);
    core::run_case(runner, "43. Router path capacity truncation smuggling (server/router.goose)", test_router_path_capacity_truncation_smuggling);
    core::run_case(runner, "44. Alt-Svc oversized proto/host/endpoints capacity safety (http/altsvc.goose)", test_altsvc_oversized_capacity_safety);

    let ok = core::finish(runner);
    assert(ok);
}
