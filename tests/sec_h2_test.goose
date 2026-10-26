// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for HTTP/2 framer validation and frame limits (RFC 9113).
import std;
import core from "..";
import wing from "..";

fn test_continuation_flood_and_interleaving(t: core::T&) {
    t.run("H2-01: CONTINUATION Flood Exceeding Frame Cap Rejection (CVE-2024-27983)") { sub =>
        var framer = wing::new_h2_security_framer();

        // 1. Initial HEADERS frame on stream 1 without END_HEADERS
        let h_hdr = wing::H2FrameHeader {
            payload_len: 100,
            frame_type: wing::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0, // No END_HEADERS
            stream_id: 1,
            valid: true,
        };
        let err0 = wing::process_incoming_frame(framer, h_hdr);
        sub.assert_eq(err0, wing::H2ErrorCode.NoError);
        sub.assert_true(framer.state == wing::H2ConnState.ExpectContinuation);

        // 2. Stream 5 valid CONTINUATION frames (allowed)
        for _ in 5 {
            let cont_hdr = wing::H2FrameHeader {
                payload_len: 100,
                frame_type: wing::H2FrameType.Continuation,
                raw_type: 0x9,
                flags: 0x0, // Not finished yet
                stream_id: 1,
                valid: true,
            };
            let err_cont = wing::process_incoming_frame(framer, cont_hdr);
            sub.assert_eq(err_cont, wing::H2ErrorCode.NoError);
        }

        // 3. 6th CONTINUATION frame (exceeds max_continuation_frames = 5) -> EnhanceYourCalm (DDoS mitigation)
        let flood_hdr = wing::H2FrameHeader {
            payload_len: 100,
            frame_type: wing::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let err_flood = wing::process_incoming_frame(framer, flood_hdr);
        sub.assert_eq(err_flood, wing::H2ErrorCode.EnhanceYourCalm, "CONTINUATION flood must be rejected with EnhanceYourCalm");
        sub.assert_true(framer.state == wing::H2ConnState.Closed);
    };

    t.run("H2-02: Stream Interleaving While Expecting CONTINUATION Rejection (RFC 9113 Section 4.3)") { sub =>
        var framer = wing::new_h2_security_framer();

        // HEADERS on stream 1 without END_HEADERS
        let h_hdr = wing::H2FrameHeader {
            payload_len: 50,
            frame_type: wing::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        wing::process_incoming_frame(framer, h_hdr);

        // Interleaved DATA frame on stream 1 (Illegal while expecting CONTINUATION)
        let data_hdr = wing::H2FrameHeader {
            payload_len: 10,
            frame_type: wing::H2FrameType.Data,
            raw_type: 0x0,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let err1 = wing::process_incoming_frame(framer, data_hdr);
        sub.assert_eq(err1, wing::H2ErrorCode.ProtocolError, "Non-CONTINUATION frame interleaved must trigger ProtocolError");

        // Reset and test interleaved CONTINUATION on DIFFERENT stream (stream 3 instead of 1)
        var framer2 = wing::new_h2_security_framer();
        wing::process_incoming_frame(framer2, h_hdr);

        let cont_other_stream = wing::H2FrameHeader {
            payload_len: 50,
            frame_type: wing::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x0,
            stream_id: 3, // Different stream!
            valid: true,
        };
        let err2 = wing::process_incoming_frame(framer2, cont_other_stream);
        sub.assert_eq(err2, wing::H2ErrorCode.ProtocolError, "CONTINUATION on different stream must trigger ProtocolError");
    };

    t.run("H2-03: Cumulative Header Block Size Bomb Rejection") { sub =>
        var framer = wing::new_h2_security_framer();

        // HEADERS with 4000 bytes
        let h_hdr = wing::H2FrameHeader {
            payload_len: 4000,
            frame_type: wing::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        wing::process_incoming_frame(framer, h_hdr);

        // CONTINUATION with 5000 bytes (total 9000 > max_header_block_bytes 8192)
        let cont_bomb = wing::H2FrameHeader {
            payload_len: 5000,
            frame_type: wing::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: 0x4, // END_HEADERS
            stream_id: 1,
            valid: true,
        };
        let err = wing::process_incoming_frame(framer, cont_bomb);
        sub.assert_eq(err, wing::H2ErrorCode.EnhanceYourCalm, "Cumulative header block > 8KB must be rejected with EnhanceYourCalm");
    };

    t.run("H2-04: Valid CONTINUATION Sequence with END_HEADERS") { sub =>
        var framer = wing::new_h2_security_framer();

        let h_hdr = wing::H2FrameHeader {
            payload_len: 200,
            frame_type: wing::H2FrameType.Headers,
            raw_type: 0x1,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        sub.assert_eq(wing::process_incoming_frame(framer, h_hdr), wing::H2ErrorCode.NoError);

        let cont_final = wing::H2FrameHeader {
            payload_len: 300,
            frame_type: wing::H2FrameType.Continuation,
            raw_type: 0x9,
            flags: wing::H2_FLAG_END_HEADERS,
            stream_id: 1,
            valid: true,
        };
        sub.assert_eq(wing::process_incoming_frame(framer, cont_final), wing::H2ErrorCode.NoError);
        sub.assert_true(framer.state == wing::H2ConnState.Idle, "State returned to Idle on END_HEADERS");
    };
}

fn test_rapid_reset_and_dos_floods(t: core::T&) {
    t.run("RESET-01: Rapid Reset Flood Defense (CVE-2023-44487)") { sub =>
        var framer = wing::new_h2_security_framer();

        // 100 RST_STREAM frames processed (under limit)
        for _ in 100 {
            let rst = wing::H2FrameHeader {
                payload_len: 4,
                frame_type: wing::H2FrameType.RstStream,
                raw_type: 0x3,
                flags: 0x0,
                stream_id: 1,
                valid: true,
            };
            let err = wing::process_incoming_frame(framer, rst);
            sub.assert_eq(err, wing::H2ErrorCode.NoError);
        }

        // 101st RST_STREAM frame (exceeds max_rapid_resets = 100) -> EnhanceYourCalm
        let rst_flood = wing::H2FrameHeader {
            payload_len: 4,
            frame_type: wing::H2FrameType.RstStream,
            raw_type: 0x3,
            flags: 0x0,
            stream_id: 1,
            valid: true,
        };
        let err_flood = wing::process_incoming_frame(framer, rst_flood);
        sub.assert_eq(err_flood, wing::H2ErrorCode.EnhanceYourCalm, "Rapid reset flood must trigger EnhanceYourCalm");
        sub.assert_true(framer.state == wing::H2ConnState.Closed);
    };

    t.run("PING-01: PING Flood Defense (CVE-2019-9512)") { sub =>
        var framer = wing::new_h2_security_framer();

        // 10 unacknowledged PING frames allowed
        for _ in 10 {
            let ping = wing::H2FrameHeader {
                payload_len: 8,
                frame_type: wing::H2FrameType.Ping,
                raw_type: 0x6,
                flags: 0x0, // Not an ACK
                stream_id: 0,
                valid: true,
            };
            sub.assert_eq(wing::process_incoming_frame(framer, ping), wing::H2ErrorCode.NoError);
        }

        // 11th unacknowledged PING -> EnhanceYourCalm
        let ping_flood = wing::H2FrameHeader {
            payload_len: 8,
            frame_type: wing::H2FrameType.Ping,
            raw_type: 0x6,
            flags: 0x0,
            stream_id: 0,
            valid: true,
        };
        sub.assert_eq(wing::process_incoming_frame(framer, ping_flood), wing::H2ErrorCode.EnhanceYourCalm);
    };
}

fn test_settings_and_stream_id_invariants(t: core::T&) {
    t.run("SETTING-01: SETTINGS_MAX_FRAME_SIZE=0 Infinite Loop Defense ") { sub =>
        // Setting 0 must trigger ProtocolError
        let err0 = wing::validate_h2_setting(0x5, 0);
        sub.assert_eq(err0, wing::H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE=0 must return ProtocolError");

        // Setting < 16,384 must trigger ProtocolError
        let err1 = wing::validate_h2_setting(0x5, 1000);
        sub.assert_eq(err1, wing::H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE < 16384 must return ProtocolError");

        // Min valid: 16,384
        let err_min = wing::validate_h2_setting(0x5, 16384);
        sub.assert_eq(err_min, wing::H2ErrorCode.NoError, "SETTINGS_MAX_FRAME_SIZE=16384 is valid");

        // Max valid: 16,777,215 (2^24 - 1)
        let err_max = wing::validate_h2_setting(0x5, 16777215);
        sub.assert_eq(err_max, wing::H2ErrorCode.NoError, "SETTINGS_MAX_FRAME_SIZE=16777215 is valid");

        // Setting > 16,777,215 must trigger ProtocolError
        let err_ovf = wing::validate_h2_setting(0x5, 20000000);
        sub.assert_eq(err_ovf, wing::H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE > 16777215 must return ProtocolError");
    };

    t.run("STREAM-01: Stream ID Parity & Connection-Level Isolation (RFC 9113 Section 5.1.1)") { sub =>
        var framer = wing::new_h2_security_framer();

        // 1. Client HEADERS on even stream (stream 2) -> ProtocolError
        let even_hdr = wing::H2FrameHeader {
            payload_len: 20,
            frame_type: wing::H2FrameType.Headers,
            raw_type: 0x1,
            flags: wing::H2_FLAG_END_HEADERS,
            stream_id: 2, // Even stream
            valid: true,
        };
        sub.assert_eq(wing::process_incoming_frame(framer, even_hdr), wing::H2ErrorCode.ProtocolError, "Client HEADERS on even stream must fail");

        // 2. Client HEADERS on stream 0 -> ProtocolError
        let stream0_hdr = wing::H2FrameHeader {
            payload_len: 20,
            frame_type: wing::H2FrameType.Headers,
            raw_type: 0x1,
            flags: wing::H2_FLAG_END_HEADERS,
            stream_id: 0,
            valid: true,
        };
        sub.assert_eq(wing::process_incoming_frame(framer, stream0_hdr), wing::H2ErrorCode.ProtocolError, "HEADERS on stream 0 must fail");

        // 3. SETTINGS on stream > 0 -> ProtocolError
        let s_hdr = wing::H2FrameHeader {
            payload_len: 6,
            frame_type: wing::H2FrameType.Settings,
            raw_type: 0x4,
            flags: 0x0,
            stream_id: 1, // Must be stream 0!
            valid: true,
        };
        sub.assert_eq(wing::process_incoming_frame(framer, s_hdr), wing::H2ErrorCode.ProtocolError, "SETTINGS on stream 1 must fail");
    };
}

fn main() {
    var runner = core::new_runner("HTTP/2 Framer Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. CONTINUATION Flood & Interleaving Guard (CVE-2024-27983)", test_continuation_flood_and_interleaving);
    core::run_case(runner, "2. Rapid Reset & Resource DoS Floods (CVE-2023-44487 & CVE-2019-9512)", test_rapid_reset_and_dos_floods);
    core::run_case(runner, "3. SETTINGS & Stream ID Invariants ", test_settings_and_stream_id_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
