// Verification suite for W3C / IETF draft-ietf-webtrans-http3-16 and RFC 9221:
// - Extended CONNECT request formatting with :protocol = webtransport
// - WebTransport session state transitions (200 OK -> active)
// - WebTransport datagram wire encoding & decoding (Session ID varint + payload)
// - RFC 9221 QUIC DATAGRAM frame encoding & decoding
import std;
import core from "..";
import wing from "..";

fn test_webtransport_session_and_datagrams(t: core::T&) {
    t.run("Extended CONNECT Initiation (draft-16)") { sub =>
        var req = wing::Request { .. };
        wing::format_webtransport_connect_request(req, "https://chat.example.com/wt-feed");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "https://chat.example.com/wt-feed", "URL matches target");

        var has_proto = false;
        var has_draft = false;
        for &h in req.headers {
            if wing::eq_ascii_fold(h.name[..], ":protocol") {
                has_proto = true;
                sub.assert_bytes_eq(h.value[..], "webtransport", ":protocol is webtransport");
            }
            if wing::eq_ascii_fold(h.name[..], "sec-webtransport-http3-draft") {
                has_draft = true;
                sub.assert_bytes_eq(h.value[..], "draft16", "Draft is draft16");
            }
        }
        sub.assert_true(has_proto, "Has :protocol header");
        sub.assert_true(has_draft, "Has draft header");

        var session = wing::WebTransportSession { session_id: 104, .. };
        var resp_200 = wing::Response { status_code: 200, .. };
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
    };
}

fn main() {
    var runner = core::new_runner("WebTransport over HTTP/3 Suite (draft-16 / RFC 9221)", core::Verbosity.Verbose);
    core::run_case(runner, "1. WebTransport Session & Datagrams", test_webtransport_session_and_datagrams);
    let ok = core::finish(runner);
    assert(ok);
}
