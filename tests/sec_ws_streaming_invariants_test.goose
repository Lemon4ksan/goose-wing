// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardening & Security Invariants Suite for WebSocket Streaming & Close Framing (RFC 6455):
// 1. Close status code validation & 1-byte close payload bans (§5.5.1 / §7.4).
// 2. Control frame length limits (<= 125 bytes) and fragmentation bans (§5.5).
// 3. Streaming UTF-8 validation across multi-byte character splits, overlong encodings, and surrogates.
import std;
import core from "..";
import wing from "..";

fn test_ws_close_payload_rfc6455_invariants(t: core::T&) {
    t.run("WS-SEC-01: Empty Close Payload and 1-Byte Payload Bans (RFC 6455 §5.5.1)") { sub =>
        // Empty payload (0 bytes) is valid: defaults to WS_STATUS_NO_STATUS (1005)
        let empty_payload: u8[0] = [];
        let code_0, reason_0, ok_0 = wing::parse_close_payload(empty_payload[..]);
        sub.assert_true(ok_0, "empty close payload is valid");
        sub.assert_eq(code_0, wing::WS_STATUS_NO_STATUS, "status code defaults to 1005");
        sub.assert_eq(reason_0.len, 0, "reason is empty");

        // 1-byte payload is strictly FORBIDDEN on the wire
        let one_byte: u8[1] = [0x03];
        let _, _, ok_1 = wing::parse_close_payload(one_byte[..]);
        sub.assert_false(ok_1, "1-byte close payload must be rejected per RFC 6455 §5.5.1");
    };

    t.run("WS-SEC-02: Forbidden Close Codes on Wire (RFC 6455 §7.4.1 & §7.4.2)") { sub =>
        // Reserved / internal codes that MUST NOT be sent on the wire
        sub.assert_false(wing::is_valid_ws_close_code(1004), "1004 (reserved) forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1005), "1005 (no status) forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1006), "1006 (abnormal) forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1015), "1015 (TLS failure) forbidden on wire");

        // Reserved unassigned range 1016..2999
        sub.assert_false(wing::is_valid_ws_close_code(1016), "1016 (reserved) forbidden");
        sub.assert_false(wing::is_valid_ws_close_code(2000), "2000 (unassigned) forbidden");
        sub.assert_false(wing::is_valid_ws_close_code(2999), "2999 (unassigned) forbidden");

        // Out of range (< 1000 or >= 5000)
        sub.assert_false(wing::is_valid_ws_close_code(999), "code 999 out of range");
        sub.assert_false(wing::is_valid_ws_close_code(5000), "code 5000 out of range");
    };

    t.run("WS-SEC-03: Valid Standard and Application-Defined Close Codes") { sub =>
        sub.assert_true(wing::is_valid_ws_close_code(1000), "1000 Normal Closure valid");
        sub.assert_true(wing::is_valid_ws_close_code(1001), "1001 Going Away valid");
        sub.assert_true(wing::is_valid_ws_close_code(1002), "1002 Protocol Error valid");
        sub.assert_true(wing::is_valid_ws_close_code(1003), "1003 Unsupported Data valid");
        sub.assert_true(wing::is_valid_ws_close_code(1007), "1007 Invalid Payload valid");
        sub.assert_true(wing::is_valid_ws_close_code(1008), "1008 Policy Violation valid");
        sub.assert_true(wing::is_valid_ws_close_code(1009), "1009 Message Too Big valid");
        sub.assert_true(wing::is_valid_ws_close_code(1010), "1010 Mandatory Extension valid");
        sub.assert_true(wing::is_valid_ws_close_code(1011), "1011 Internal Error valid");

        // Valid registered/private ranges 3000..4999
        sub.assert_true(wing::is_valid_ws_close_code(3000), "3000 (registered) valid");
        sub.assert_true(wing::is_valid_ws_close_code(4000), "4000 (private use) valid");
        sub.assert_true(wing::is_valid_ws_close_code(4999), "4999 (private use) valid");
    };
}

fn test_ws_control_frame_invariants(t: core::T&) {
    t.run("WS-SEC-04: Control Frame Payload > 125 Bytes Forbidden (RFC 6455 §5.5)") { sub =>
        // PING frame with payload length 126 (0x7E) encoded with extended 16-bit length
        let bad_ping: u8[4] = [
            0x89, // FIN=1, Opcode=9 (Ping)
            0x7E, // Mask=0, Len=126
            0x00, 0x7E, // Extended 16-bit length 126
        ];
        let _, ok = wing::parse_ws_frame_header(bad_ping[..]);
        sub.assert_false(ok, "Control frame with payload length > 125 must be rejected");
    };

    t.run("WS-SEC-05: Fragmented Control Frame Forbidden (RFC 6455 §5.5)") { sub =>
        // PING frame with FIN=0 (fragmented)
        let frag_ping: u8[2] = [
            0x09, // FIN=0 (bit 7=0), Opcode=9 (Ping)
            0x00, // Mask=0, Len=0
        ];
        let _, ok = wing::parse_ws_frame_header(frag_ping[..]);
        sub.assert_false(ok, "Fragmented control frame (FIN=0) must be rejected");
    };

    t.run("WS-SEC-06: Undefined Opcodes Rejected (RFC 6455 §5.2)") { sub =>
        // Opcode 3 (reserved non-control)
        let unk_op3: u8[2] = [0x83, 0x00];
        let _, ok3 = wing::parse_ws_frame_header(unk_op3[..]);
        sub.assert_false(ok3, "Unknown opcode 0x3 must be rejected");

        // Opcode 0xB (reserved control)
        let unk_opB: u8[2] = [0x8B, 0x00];
        let _, okB = wing::parse_ws_frame_header(unk_opB[..]);
        sub.assert_false(okB, "Unknown control opcode 0xB must be rejected");
    };
}

fn test_ws_streaming_utf8_invariants(t: core::T&) {
    t.run("WS-SEC-07: Overlong Encodings and UTF-16 Surrogates Rejected") { sub =>
        // Overlong 2-byte NUL: 0xC0 0x80
        let overlong_nul: u8[2] = [0xC0, 0x80];
        sub.assert_false(core::validate_utf8(overlong_nul[..]), "overlong NUL 0xC0 0x80 must be rejected");

        // Overlong 3-byte: 0xE0 0x80 0xAF
        let overlong_3: u8[3] = [0xE0, 0x80, 0xAF];
        sub.assert_false(core::validate_utf8(overlong_3[..]), "overlong 3-byte sequence must be rejected");

        // High surrogate half: 0xED 0xA0 0x80 (U+D800)
        let surrogate_hi: u8[3] = [0xED, 0xA0, 0x80];
        sub.assert_false(core::validate_utf8(surrogate_hi[..]), "UTF-16 high surrogate must be rejected");

        // Low surrogate half: 0xED 0xBF 0xBF (U+DFFF)
        let surrogate_lo: u8[3] = [0xED, 0xBF, 0xBF];
        sub.assert_false(core::validate_utf8(surrogate_lo[..]), "UTF-16 low surrogate must be rejected");
    };

    t.run("WS-SEC-08: Streaming UTF-8 across Split Multi-Byte Characters") { sub =>
        // Euro sign € is 3 bytes: 0xE2 0x82 0xAC
        // Chunk 1: "a" + [0xE2, 0x82] (incomplete 3-byte sequence, is_final=false)
        let chunk1: u8[3] = ['a', 0xE2, 0x82];
        let valid_len1, ok1 = core::validate_utf8_streaming(chunk1[..], false);
        sub.assert_true(ok1, "partial UTF-8 sequence accepted when is_final=false");
        sub.assert_eq(valid_len1, 1, "valid prefix length is 1 ('a')");

        // When is_final=true, partial UTF-8 sequence at end must fail
        let _, ok1_final = core::validate_utf8_streaming(chunk1[..], true);
        sub.assert_false(ok1_final, "partial UTF-8 sequence rejected when is_final=true");

        // Chunk 2: [0xAC] + "b" (completes Euro sign: 0xE2 0x82 0xAC + 'b')
        let full_msg: u8[5] = ['a', 0xE2, 0x82, 0xAC, 'b'];
        let valid_full, ok_full = core::validate_utf8_streaming(full_msg[..], true);
        sub.assert_true(ok_full, "assembled message is fully valid UTF-8");
        sub.assert_eq(valid_full, 5, "entire 5-byte message validated");
    };
}

fn main() {
    var runner = core::new_runner("WebSocket Security & Streaming Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Close Payload & Wire Status Code Invariants (§5.5.1 / §7.4)", test_ws_close_payload_rfc6455_invariants);
    core::run_case(runner, "2. Control Frame Limits & Fragmentation Bans (§5.5)", test_ws_control_frame_invariants);
    core::run_case(runner, "3. Streaming UTF-8 Invariants & Surrogate Rejection", test_ws_streaming_utf8_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
