// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardening & Security Invariants Suite for HTTP/2 Connection State Machine (RFC 9113):
// 1. SETTINGS & PING frame invariants (length % 6 == 0, ACK length == 0, Stream 0 binding).
// 2. Flow control window arithmetic, 31-bit overflow guards, and zero-increment bans.
// 3. CONTINUATION flood defense (CVE-2024-27983) and illegal frame interleaving bans.
import std;
import core from "..";
import wing from "..";

fn test_h2_settings_and_ping_invariants(t: core::T&) {
    t.run("H2-SEC-01: SETTINGS ACK with Non-Zero Length must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = wing::new_h2_connection(0);
        let hdr = wing::FrameHeader {
            length: 6, // Length != 0 with ACK is illegal per RFC 9113 §6.5
            frame_type: wing::FRAME_SETTINGS,
            flags: wing::FLAG_ACK,
            stream_id: 0,
        };
        let err = wing::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, wing::ERR_FRAME_SIZE_ERROR, "SETTINGS with ACK and length > 0 must trigger FRAME_SIZE_ERROR");
    };

    t.run("H2-SEC-02: SETTINGS with Length not multiple of 6 must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = wing::new_h2_connection(0);
        let hdr = wing::FrameHeader {
            length: 5, // Not multiple of 6
            frame_type: wing::FRAME_SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        let err = wing::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, wing::ERR_FRAME_SIZE_ERROR, "SETTINGS length not multiple of 6 must trigger FRAME_SIZE_ERROR");
    };

    t.run("H2-SEC-03: SETTINGS or PING on Stream != 0 must trigger PROTOCOL_ERROR") { sub =>
        var conn = wing::new_h2_connection(0);

        // SETTINGS on stream 1
        let hdr_set = wing::FrameHeader {
            length: 6,
            frame_type: wing::FRAME_SETTINGS,
            flags: 0,
            stream_id: 1, // Illegal: MUST be stream 0 per RFC 9113 §6.5
        };
        let err_set = wing::on_ingress_frame_header(conn, hdr_set, 0);
        sub.assert_eq(err_set, wing::ERR_PROTOCOL_ERROR, "SETTINGS on stream != 0 must trigger PROTOCOL_ERROR");

        // PING on stream 1
        let hdr_ping = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_PING,
            flags: 0,
            stream_id: 1, // Illegal: MUST be stream 0 per RFC 9113 §6.7
        };
        let err_ping = wing::on_ingress_frame_header(conn, hdr_ping, 0);
        sub.assert_eq(err_ping, wing::ERR_PROTOCOL_ERROR, "PING on stream != 0 must trigger PROTOCOL_ERROR");
    };

    t.run("H2-SEC-04: PING with Length != 8 must trigger FRAME_SIZE_ERROR") { sub =>
        var conn = wing::new_h2_connection(0);
        let hdr = wing::FrameHeader {
            length: 7, // Illegal: MUST be exactly 8 per RFC 9113 §6.7
            frame_type: wing::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        let err = wing::on_ingress_frame_header(conn, hdr, 0);
        sub.assert_eq(err, wing::ERR_FRAME_SIZE_ERROR, "PING with length != 8 must trigger FRAME_SIZE_ERROR");
    };
}

fn test_h2_window_update_and_flow_control(t: core::T&) {
    t.run("H2-SEC-05: WINDOW_UPDATE Increment 0 is Forbidden (RFC 9113 §6.9)") { sub =>
        var conn = wing::new_h2_connection(0);
        let err_conn = wing::apply_window_update(conn, 0, 0);
        sub.assert_eq(err_conn, wing::ERR_PROTOCOL_ERROR, "WINDOW_UPDATE with increment 0 on connection must trigger PROTOCOL_ERROR");

        let err_str = wing::apply_window_update(conn, 1, 0);
        sub.assert_eq(err_str, wing::ERR_PROTOCOL_ERROR, "WINDOW_UPDATE with increment 0 on stream must trigger PROTOCOL_ERROR");
    };

    t.run("H2-SEC-06: Connection Window Overflow beyond 2^31 - 1 triggers FLOW_CONTROL_ERROR") { sub =>
        var conn = wing::new_h2_connection(0);
        // Default conn_send_window is 65535
        // Adding 0x7FFFFFFF will overflow MAX_INITIAL_WINDOW_SIZE (0x7FFFFFFF)
        let err = wing::apply_window_update(conn, 0, 0x7FFFFFFF);
        sub.assert_eq(err, wing::ERR_FLOW_CONTROL_ERROR, "Connection window overflow must trigger FLOW_CONTROL_ERROR");
    };

    t.run("H2-SEC-07: Excessive Initial Window Updates Flood Defense (CVE-2026-78669)") { sub =>
        var conn = wing::new_h2_connection(0);
        var hit_flood = false;
        for _ in 20 {
            let err = wing::apply_peer_initial_window_size_delta(conn, 65535);
            if err == wing::ERR_ENHANCE_YOUR_CALM {
                hit_flood = true;
                break;
            }
        }
        sub.assert_true(hit_flood, "Repeated initial window size delta flood must trigger ENHANCE_YOUR_CALM");
    };
}

fn test_h2_continuation_flood_and_interleaving(t: core::T&) {
    t.run("H2-SEC-08: Interleaved Frame During Continuation Sequence Forbidden (RFC 9113 §4.3)") { sub =>
        var conn = wing::new_h2_connection(0);

        // 1. Initial HEADERS frame on stream 1 without END_HEADERS flag
        let h_hdr = wing::FrameHeader {
            length: 100,
            frame_type: wing::FRAME_HEADERS,
            flags: 0, // FLAG_END_HEADERS not set
            stream_id: 1,
        };
        let err_h = wing::on_ingress_frame_header(conn, h_hdr, 0);
        sub.assert_eq(err_h, wing::ERR_NO_ERROR, "HEADERS frame enters continuation state cleanly");
        sub.assert_eq(conn.continuation_stream_id, 1, "connection expects continuation on stream 1");

        // 2. Interleaved PING frame on stream 0 arrives before CONTINUATION
        let ping_hdr = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        let err_ping = wing::on_ingress_frame_header(conn, ping_hdr, 0);
        sub.assert_eq(err_ping, wing::ERR_PROTOCOL_ERROR, "Interleaved PING during continuation sequence must trigger PROTOCOL_ERROR per RFC 9113 §4.3");

        // 3. Interleaved DATA on stream 1 arrives before CONTINUATION
        let data_hdr = wing::FrameHeader {
            length: 50,
            frame_type: wing::FRAME_DATA,
            flags: 0,
            stream_id: 1,
        };
        let err_data = wing::on_ingress_frame_header(conn, data_hdr, 0);
        sub.assert_eq(err_data, wing::ERR_PROTOCOL_ERROR, "Interleaved DATA during continuation sequence must trigger PROTOCOL_ERROR per RFC 9113 §4.3");
    };

    t.run("H2-SEC-09: CONTINUATION on Different Stream ID Rejected (RFC 9113 §6.10)") { sub =>
        var conn = wing::new_h2_connection(0);

        // HEADERS on stream 3 without END_HEADERS
        let h_hdr = wing::FrameHeader {
            length: 50,
            frame_type: wing::FRAME_HEADERS,
            flags: 0,
            stream_id: 3,
        };
        let _ = wing::on_ingress_frame_header(conn, h_hdr, 0);

        // CONTINUATION arrives on stream 5 instead of 3
        let cont_hdr = wing::FrameHeader {
            length: 50,
            frame_type: wing::FRAME_CONTINUATION,
            flags: 0,
            stream_id: 5,
        };
        let err_cont = wing::on_ingress_frame_header(conn, cont_hdr, 0);
        sub.assert_eq(err_cont, wing::ERR_PROTOCOL_ERROR, "CONTINUATION on different stream ID must trigger PROTOCOL_ERROR per RFC 9113 §6.10");
    };
}

fn main() {
    var runner = core::new_runner("HTTP/2 FSM & Control Frame Security Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. SETTINGS & PING Frame Wire Invariants (RFC 9113 §6.5/§6.7)", test_h2_settings_and_ping_invariants);
    core::run_case(runner, "2. Flow Control Window Arithmetic & Overflow Guards (RFC 9113 §6.9)", test_h2_window_update_and_flow_control);
    core::run_case(runner, "3. CONTINUATION Flood & Interleaving Defenses (RFC 9113 §4.3/§6.10)", test_h2_continuation_flood_and_interleaving);

    let ok = core::finish(runner);
    assert(ok);
}
