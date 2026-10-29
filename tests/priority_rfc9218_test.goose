// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 9218 Extensible HTTP Priority:
// - Structured Field priority header parsing (u=0..7, i=?1/?0)
// - Unknown parameter tolerance per RFC 9218 Section 4
// - Priority header canonical serialization
// - HTTP/2 PRIORITY_UPDATE frame encoding, decoding, and validation
// - HTTP/3 PRIORITY_UPDATE frame processing and connection state update
import std;
import core from "..";
import wing from "..";

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
        wing::encode_priority_update_payload(5, prio, frame_buf);

        sub.assert_gt(frame_buf.len, 4, "Frame payload encoded");

        let stream_id, parsed_prio, err = wing::parse_priority_update_payload(frame_buf[..]);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "No protocol error");
        sub.assert_eq(stream_id, 5, "Stream ID matches 5");
        sub.assert_eq(parsed_prio.urgency, 1, "Urgency matches 1");
        sub.assert_true(parsed_prio.incremental, "Incremental matches true");

        // Stream ID 0 rejection (RFC 9218 §7.1)
        var zero_id_buf: u8[8] = [0, 0, 0, 0, 'u' as u8, '=' as u8, '2' as u8, 0];
        let _, _, err_zero = wing::parse_priority_update_payload(zero_id_buf[..]);
        sub.assert_eq(err_zero, wing::ERR_PROTOCOL_ERROR, "Stream 0 rejected with PROTOCOL_ERROR");

        // Truncated payload (< 4 bytes)
        var trunc_buf: u8[2] = [0, 1];
        let _, _, err_trunc = wing::parse_priority_update_payload(trunc_buf[..]);
        sub.assert_eq(err_trunc, wing::ERR_FRAME_SIZE_ERROR, "Truncated frame rejected with FRAME_SIZE_ERROR");
    };
}

fn test_h3_priority_update_integration(t: core::T&) {
    t.run("HTTP/3 PRIORITY_UPDATE Control Frame (RFC 9218 §7.2)") { sub =>
        // Create an H3Connection with a request stream
        var conn = wing::H3Connection { .. };
        conn.state = wing::H3ConnState.Active;
        let req_id, ok_req = wing::open_request_stream(conn);
        sub.assert_true(ok_req, "Created request stream");

        // Verify initial priority is default u=3, i=false
        let init_prio, ok_init = wing::get_stream_priority(conn, req_id);
        sub.assert_true(ok_init, "Initial priority retrieved");
        sub.assert_eq(init_prio.urgency, 3, "Initial urgency 3");
        sub.assert_false(init_prio.incremental, "Initial incremental false");

        // Encode a PRIORITY_UPDATE frame for stream 0
        var update_buf: u8[>..] = [];
        let new_prio = wing::HttpPriority { urgency: 0, incremental: true };
        let enc_ok = wing::encode_h3_priority_update_request(update_buf, req_id, new_prio);
        sub.assert_true(enc_ok, "Encoded H3 PRIORITY_UPDATE frame");

        // Deliver control stream type 0x00 and SETTINGS frame to initialize control stream
        conn.peer_control_stream_id = 3;
        var init_ctrl: u8[>..] = [];
        init_ctrl.push(0x00 as u8); // Control stream type
        var settings = wing::H3Settings { .. };
        wing::encode_h3_settings_frame(init_ctrl, settings);
        let err_init = wing::handle_stream_data(conn, 3, false, init_ctrl[..], false);
        sub.assert_eq(err_init, wing::H3_ERR_NO_ERROR, "Control stream initialized");

        // Now deliver PRIORITY_UPDATE frame on unidirectional stream 3
        let err_pu = wing::handle_stream_data(conn, 3, false, update_buf[..], false);
        sub.assert_eq(err_pu, wing::H3_ERR_NO_ERROR, "PRIORITY_UPDATE handled cleanly");

        // Verify that stream 0 priority has been dynamically updated!
        let updated_prio, ok_up = wing::get_stream_priority(conn, req_id);
        sub.assert_true(ok_up, "Updated priority retrieved");
        sub.assert_eq(updated_prio.urgency, 0, "Urgency dynamically updated to 0");
        sub.assert_true(updated_prio.incremental, "Incremental dynamically updated to true");
    };
}

fn main() {
    var runner = core::new_runner("RFC 9218 Extensible HTTP Priority Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Priority Parsing", test_priority_parsing);
    core::run_case(runner, "2. Priority Serialization", test_priority_serialization);
    core::run_case(runner, "3. H2 Priority Update Frame", test_h2_priority_update_frame);
    core::run_case(runner, "4. H3 Priority Update Integration", test_h3_priority_update_integration);
    let ok = core::finish(runner);
    assert(ok);
}
