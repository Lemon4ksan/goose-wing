// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for W3C / IETF draft-ietf-webtrans-http3-16 and RFC 9221:
// - Extended CONNECT request formatting & validation (:protocol = webtransport)
// - WebTransport session state transitions & lifecycle (open, drain, close)
// - WebTransport unidirectional (0x54) and bidirectional (0x41) stream framing
// - WebTransport datagram wire encoding & decoding (Session ID varint + payload)
// - RFC 9221 QUIC DATAGRAM frame encoding & decoding
// - HTTP/3 error code translation with GREASE skipping
// - WebTransport capsule codecs (close, drain, reset_stream, stop_sending)
import std;
import core from "..";
import wing from "..";

fn test_webtransport_session_and_datagrams(t: core::T&) {
    t.run("Extended CONNECT Initiation (draft-16)") { sub =>
        var req = wing::Request { .. };
        wing::format_webtransport_connect_request(req, "https://chat.example.com/wt-feed");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "https://chat.example.com/wt-feed", "URL matches target");

        sub.assert_true(req.has_header(":protocol"), "Has :protocol header");
        sub.assert_bytes_eq(req.header(":protocol"), "webtransport", ":protocol is webtransport");
        sub.assert_true(req.has_header("sec-webtransport-http3-draft"), "Has draft header");
        sub.assert_bytes_eq(req.header("sec-webtransport-http3-draft"), "draft16", "Draft is draft16");

        sub.assert_true(wing::is_webtransport_connect_request(req), "is_webtransport_connect_request returns true");

        var bad_req = wing::Request { .. };
        sub.assert_false(wing::is_webtransport_connect_request(bad_req), "Non-CONNECT request is rejected");

        var session = wing::WebTransportSession { session_id: 104, .. };
        var resp_200 = wing::Response { status_code: 200, .. };
        wing::format_webtransport_connect_response(resp_200);
        sub.assert_bytes_eq(resp_200.header("sec-webtransport-http3-draft"), "draft16", "Response draft header is draft16");

        let ok = wing::handle_webtransport_response(resp_200, session);
        sub.assert_true(ok, "Session activated on 200 OK");
        sub.assert_true(session.is_active, "Session is active");

        var resp_500 = wing::Response { status_code: 500, .. };
        let fail = wing::handle_webtransport_response(resp_500, session);
        sub.assert_false(fail, "Session rejected on 500 Error");
        sub.assert_false(session.is_active, "Session deactivated");
    };

    t.run("WebTransport Datagram Framing") { sub =>
        let payload = "RAW_UNRELIABLE_TELEMETRY_SAMPLE";
        let session_id: u64 = 42;

        var wire: u8[>..] = [];
        wing::encode_webtransport_datagram(session_id, payload, wire);
        sub.assert_gt(wire.len, payload.len, "Framing includes varint session id");

        var decoded = wing::WebTransportDatagram { .. };
        let ok_dec = wing::decode_webtransport_datagram(wire[..], decoded);
        sub.assert_true(ok_dec, "Datagram decoded");
        sub.assert_eq(decoded.session_id, 42, "Session ID is 42");
        sub.assert_bytes_eq(decoded.payload[..], payload, "Payload matches original bytes");
    };

    t.run("RFC 9221 QUIC DATAGRAM Frame Codec") { sub =>
        let datagram_msg = "LOW_LATENCY_POSITION_UPDATE_X100_Y200";
        var frame_wire: u8[>..] = [];
        wing::encode_quic_datagram_frame(datagram_msg, frame_wire);

        sub.assert_gt(frame_wire.len, datagram_msg.len, "Frame wire includes type and length varints");

        var extracted_msg: u8[>..] = [];
        let ok_frame = wing::decode_quic_datagram_frame(frame_wire[..], extracted_msg);
        sub.assert_true(ok_frame, "QUIC DATAGRAM frame decoded");
        sub.assert_bytes_eq(extracted_msg[..], datagram_msg, "Extracted payload matches verbatim");

        // Oversized datagram (> 1500B) rejection without panic
        var huge_dgram: u8[>..] = [];
        huge_dgram.push(0x01); // session_id = 1
        for i in 1600 { huge_dgram.push('X'); }
        var dec_huge = wing::WebTransportDatagram { .. };
        sub.assert_false(wing::decode_webtransport_datagram(huge_dgram[..], dec_huge), "Oversized >1500B datagram rejected safely");

        // Truncated QUIC DATAGRAM frame with huge 62-bit varint length rejected without overflow
        let trunc_quic: u8[9] = [0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        var out_trunc: u8[>..] = [];
        sub.assert_false(wing::decode_quic_datagram_frame(trunc_quic[..], out_trunc), "Huge 62-bit varint length rejected safely");
    };
}

fn test_webtransport_stream_framing(t: core::T&) {
    t.run("Unidirectional Stream Framing (Type 0x54)") { sub =>
        let session_id: u64 = 256;
        var wire: u8[..32] = [];
        wing::encode_webtransport_uni_stream_header(session_id, wire);

        // 0x54 (84) > 63, so RFC 9000 varint encodes it as 2 bytes [0x40, 0x54]
        sub.assert_eq(wire[0], 0x40, "Varint 2-byte prefix 0x40");
        sub.assert_eq(wire[1], 0x54, "Stream type is 0x54");

        var decoded = wing::WebTransportUniStreamHeader { .. };
        let ok = wing::decode_webtransport_uni_stream_header(wire[..], decoded);
        sub.assert_true(ok, "Uni stream header decoded successfully");
        sub.assert_eq(decoded.session_id, 256, "Decoded session ID matches");
        sub.assert_eq(decoded.header_len, wire.len, "Header length matches encoded bytes");

        // Invalid stream type
        var invalid_wire: u8[..32] = [];
        invalid_wire.push(0x40);
        invalid_wire.push(0x55);
        invalid_wire.push(0x01);
        var bad_decoded = wing::WebTransportUniStreamHeader { .. };
        sub.assert_false(wing::decode_webtransport_uni_stream_header(invalid_wire[..], bad_decoded), "Rejected non-0x54 stream type");
    };

    t.run("Bidirectional Stream Opening Framing (Signal 0x41)") { sub =>
        let session_id: u64 = 1024;
        var wire: u8[..32] = [];
        wing::encode_webtransport_bidi_stream_header(session_id, wire);

        // 0x41 (65) > 63, so RFC 9000 varint encodes it as 2 bytes [0x40, 0x41]
        sub.assert_eq(wire[0], 0x40, "Varint 2-byte prefix 0x40");
        sub.assert_eq(wire[1], 0x41, "Stream signal is 0x41");

        var decoded = wing::WebTransportBidiStreamHeader { .. };
        let ok = wing::decode_webtransport_bidi_stream_header(wire[..], decoded);
        sub.assert_true(ok, "Bidi stream header decoded successfully");
        sub.assert_eq(decoded.session_id, 1024, "Decoded session ID matches");
        sub.assert_eq(decoded.header_len, wire.len, "Header length matches encoded bytes");

        // Invalid signal
        var invalid_wire: u8[..32] = [];
        invalid_wire.push(0x40);
        invalid_wire.push(0x42);
        invalid_wire.push(0x02);
        var bad_decoded = wing::WebTransportBidiStreamHeader { .. };
        sub.assert_false(wing::decode_webtransport_bidi_stream_header(invalid_wire[..], bad_decoded), "Rejected non-0x41 signal");
    };
}

fn test_webtransport_error_mapping(t: core::T&) {
    t.run("Application Error Translation to HTTP/3 and Back") { sub =>
        let test_codes: u32[7] = [0, 1, 29, 30, 31, 1000, 0xFFFFFFFF];
        for i in 7 {
            let app_err = test_codes[i];
            let h3_err = wing::webtransport_code_to_http_code(app_err);

            sub.assert_ge(h3_err, wing::WEBTRANSPORT_ERROR_FIRST, "H3 error >= lower bound");
            sub.assert_le(h3_err, wing::WEBTRANSPORT_ERROR_LAST, "H3 error <= upper bound");

            // Verify no GREASE collision: (h3_err - 0x21) % 0x1F != 0
            let is_grease = ((h3_err - 0x21) % 0x1F) == 0;
            sub.assert_false(is_grease, "Mapped H3 error is not a GREASE point");

            let recovered, ok = wing::http_code_to_webtransport_code(h3_err);
            sub.assert_true(ok, "HTTP error translated back to WebTransport error");
            sub.assert_eq(recovered, app_err, "Recovered application error matches original");
        }

        // Out of bound checks
        let _, bad1 = wing::http_code_to_webtransport_code(wing::WEBTRANSPORT_ERROR_FIRST - 1);
        sub.assert_false(bad1, "Underflow H3 error rejected");

        let _, bad2 = wing::http_code_to_webtransport_code(wing::WEBTRANSPORT_ERROR_LAST + 1);
        sub.assert_false(bad2, "Overflow H3 error rejected");
    };
}

fn test_webtransport_capsules(t: core::T&) {
    t.run("CLOSE_WEBTRANSPORT_SESSION Capsule") { sub =>
        let err_code: u32 = 404;
        let reason = "RESOURCE_NOT_FOUND_ON_STREAM";
        var wire: u8[..256] = [];
        wing::encode_webtransport_close_session(err_code, reason, wire);

        var c, ok_c = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "HTTP Capsule parsed from wire");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_CLOSE_WEBTRANSPORT, "Capsule type is CLOSE_WEBTRANSPORT");

        var decoded = wing::WebTransportCloseSession { .. };
        let ok_dec = wing::decode_webtransport_close_session(c.payload, decoded);
        sub.assert_true(ok_dec, "Close session payload decoded");
        sub.assert_eq(decoded.error_code, 404, "Error code matches 404");
        sub.assert_bytes_eq(decoded.reason[..], reason, "Reason matches original message");
    };

    t.run("DRAIN_WEBTRANSPORT_SESSION Capsule") { sub =>
        var wire: u8[..64] = [];
        wing::encode_webtransport_drain_session(wire);

        var c, ok_c = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "Drain capsule parsed");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_DRAIN_WEBTRANSPORT, "Capsule type is DRAIN_WEBTRANSPORT");
        sub.assert_true(wing::decode_webtransport_drain_session(c.payload), "Drain payload is valid (0-length)");

        var bad_payload: u8[2] = [1, 2];
        sub.assert_false(wing::decode_webtransport_drain_session(bad_payload[..]), "Non-empty drain payload is invalid");
    };

    t.run("Stream Reset and Stop Sending Capsules") { sub =>
        // WT_RESET_STREAM
        var r_wire: u8[..64] = [];
        wing::encode_webtransport_reset_stream(12, 503, r_wire);
        var c_r, ok_cr = wing::parse_http_capsule(r_wire[..]);
        sub.assert_true(ok_cr, "Reset stream capsule parsed");
        sub.assert_eq(c_r.capsule_type, wing::CAPSULE_WT_RESET_STREAM, "Capsule type is WT_RESET_STREAM");

        var reset_dec = wing::WebTransportStreamReset { .. };
        sub.assert_true(wing::decode_webtransport_reset_stream(c_r.payload, reset_dec), "Reset payload decoded");
        sub.assert_eq(reset_dec.stream_id, 12, "Reset stream ID is 12");
        sub.assert_eq(reset_dec.error_code, 503, "Reset error code is 503");

        // WT_STOP_SENDING
        var s_wire: u8[..64] = [];
        wing::encode_webtransport_stop_sending(18, 499, s_wire);
        var c_s, ok_cs = wing::parse_http_capsule(s_wire[..]);
        sub.assert_true(ok_cs, "Stop sending capsule parsed");
        sub.assert_eq(c_s.capsule_type, wing::CAPSULE_WT_STOP_SENDING, "Capsule type is WT_STOP_SENDING");

        var stop_dec = wing::WebTransportStreamStopSending { .. };
        sub.assert_true(wing::decode_webtransport_stop_sending(c_s.payload, stop_dec), "Stop sending payload decoded");
        sub.assert_eq(stop_dec.stream_id, 18, "Stop sending stream ID is 18");
        sub.assert_eq(stop_dec.error_code, 499, "Stop sending error code is 499");
    };
}

fn test_webtransport_session_lifecycle(t: core::T&) {
    t.run("Session Transitions: Active -> Draining -> Closed") { sub =>
        var session = wing::WebTransportSession { session_id: 88, is_active: true, .. };
        sub.assert_true(wing::is_webtransport_session_open(session), "Session is initially open");

        wing::drain_webtransport_session(session);
        sub.assert_true(session.is_draining, "Session is draining");
        sub.assert_true(session.is_active, "Session is still active while draining");
        sub.assert_false(wing::is_webtransport_session_open(session), "is_webtransport_session_open is false while draining");

        wing::close_webtransport_session(session, 200, "CLEAN_DISCONNECT");
        sub.assert_false(session.is_active, "Session is closed");
        sub.assert_eq(session.close_code, 200, "Close code matches");
        sub.assert_bytes_eq(session.close_reason[..], "CLEAN_DISCONNECT", "Close reason matches");
        sub.assert_false(wing::is_webtransport_session_open(session), "Closed session is not open");
    };
}

fn main() {
    var runner = core::new_runner("WebTransport over HTTP/3 Suite (draft-16 / RFC 9221)", core::Verbosity.Verbose);
    core::run_case(runner, "1. WebTransport Session & Datagrams", test_webtransport_session_and_datagrams);
    core::run_case(runner, "2. WebTransport Stream Framing", test_webtransport_stream_framing);
    core::run_case(runner, "3. WebTransport Error Code Mapping", test_webtransport_error_mapping);
    core::run_case(runner, "4. WebTransport Capsule Codecs", test_webtransport_capsules);
    core::run_case(runner, "5. WebTransport Session Lifecycle", test_webtransport_session_lifecycle);
    let ok = core::finish(runner);
    assert(ok);
}
