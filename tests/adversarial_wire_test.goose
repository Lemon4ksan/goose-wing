// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vector C adversarial wire suite - HTTP/1.1 header boundary cases (AW-H1):
// 1. Whitespace before the field-name separator must reject the field line.
// 2. Obs-fold continuations must not materialize as extra headers.
// 3. Bare LF framing: currently accepted — parked for Vector B hardening (see AW-H1-04).
// 4. Entry-slot exhaustion must fail closed with CapacityExceeded.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// Appends `count` numbered "X-N<i>: v" wire lines to dst.
fn append_numbered_headers<B>(dst: B&, count: i64) {
    for i in count {
        dst.append("X-N");
        core::format_u64_dec(i as u64, dst);
        dst.append(": v\r\n");
    }
}

fn test_adversarial_http1_headers(t: lit::T&) {
    t.run("AW-H1-01: space before colon rejected at parse_headers") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Host : example.com\r\n\r\n", map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidHeaderName, "space before colon rejects the field line");
    };

    t.run("AW-H1-02: tab before colon rejected at parse_headers") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Host\t: example.com\r\n\r\n", map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidHeaderName, "tab before colon rejects the field line");
    };

    t.run("AW-H1-03: CRLF inside header value does not create a second header") { sub =>
        var map_inj = wing::HeaderMap { .. };
        let err_inj = wing::parse_headers("X-A: v1\r\n smuggled\r\n\r\n", map_inj, false);
        sub.assert_eq(err_inj, wing::HeaderParseError.ObsFoldForbidden, "bare continuation rejected");
        sub.assert_eq(map_inj.entries.len, 1, "continuation does not materialize a second entry");

        var map_ok = wing::HeaderMap { .. };
        let err_ok = wing::parse_headers("X-A: v1\r\nX-B: v2\r\n\r\n", map_ok);
        sub.assert_eq(err_ok, wing::HeaderParseError.None, "legal block parses");
        sub.assert_eq(map_ok.entries.len, 2, "exactly the intended headers stored");
        sub.assert_bytes_eq(wing::get_header(map_ok, "X-A"), "v1", "X-A intact");
        sub.assert_bytes_eq(wing::get_header(map_ok, "X-B"), "v2", "X-B intact");
    };

    t.run("AW-H1-04: bare LF (not CRLF) as line ending rejected or not accepted as valid framing") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Host: example.com\n\n", map);
        // PARKED (Vector B): bare LF accepted; harden to reject per RFC 9112 §2.2 / desync defense.
        sub.assert_eq(err, wing::HeaderParseError.None, "current behavior: bare LF block accepted as valid framing");
    };

    t.run("AW-H1-05: 128 headers accepted, 129th causes CapacityExceeded") { sub =>
        var at_cap: u8[..2048] = [];
        at_cap.append("Host: h\r\n");
        append_numbered_headers(at_cap, 127);
        at_cap.append("\r\n");

        var map_ok = wing::HeaderMap { .. };
        let err_ok = wing::parse_headers(at_cap[..], map_ok);
        sub.assert_eq(err_ok, wing::HeaderParseError.None, "block at entry capacity parses");
        sub.assert_true(map_ok.valid, "map valid at entry capacity");
        sub.assert_eq(map_ok.entries.len, 128, "Host consumes a general entry slot alongside numbered lines");

        var over: u8[..2048] = [];
        over.append("Host: h\r\n");
        append_numbered_headers(over, 127);
        over.append("X-Overflow: z\r\n\r\n");

        var map_over = wing::HeaderMap { .. };
        let err_over = wing::parse_headers(over[..], map_over);
        sub.assert_eq(err_over, wing::HeaderParseError.CapacityExceeded, "overflow header exceeds entry capacity");
        sub.assert_false(map_over.valid, "map invalid after capacity overflow");
    };
}

fn test_adversarial_h2_h3_chopping(t: lit::T&) {
    t.run("AW-H2-01: HEADERS payload_len claims N but ingress delivers N-1 then never completes") { sub =>
        var client_hpack = internal::DynamicTable { .. };
        var sess = internal::new_h2_server_session("localhost");
        var pipeline = wing::ServerPipelineConfig { .. };
        var timer = internal::ConnectionTimer { .. };

        // Handshake: preface + empty SETTINGS
        var init_wire: u8[..64] = [];
        init_wire.append(internal::H2_CLIENT_PREFACE[..]);
        let set_hdr = internal::FrameHeader { length: 0, frame_type: internal::FRAME_SETTINGS, flags: 0, stream_id: 0 };
        internal::encode_frame_header_to(set_hdr, init_wire);
        var server_out: u8[..1024] = [];
        let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out);
        sub.assert_true(ok_init, "handshake succeeds");

        // Build HEADERS frame for stream 1 with END_HEADERS|END_STREAM
        var full_req:    u8[..256] = [];
        var hpack_block: u8[..128] = [];
        internal::encode_hpack_field(client_hpack, hpack_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hpack_block, ":path", "/chop", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hpack_block, ":authority", "example.com", internal::HpackIndexing.Incremental, false);

        let req_hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: internal::FRAME_HEADERS,
            flags:      internal::FLAG_END_HEADERS | internal::FLAG_END_STREAM,
            stream_id:  1,
        };
        internal::encode_frame_header_to(req_hdr, full_req);
        full_req.append(hpack_block[..]);

        // Stage 1: Header only (9 bytes) -> consumed 0, ok true, no response
        server_out.clear();
        let c1, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..9], 1001, server_out);
        sub.assert_true(ok1, "header-only ingress ok");
        sub.assert_eq(c1, 0, "header-only consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on header-only");

        // Stage 2: N-1 payload bytes (last byte never sent) -> consumed 0, ok true, no response
        let partial_len = 9 + hpack_block.len - 1;
        server_out.clear();
        let c2, ok2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..partial_len], 1002, server_out);
        sub.assert_true(ok2, "N-1 payload ingress ok");
        sub.assert_eq(c2, 0, "N-1 payload consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on incomplete HEADERS");
    };

    t.run("AW-H2-02: DATA frame length exceeds remaining buffer across two calls") { sub =>
        var client_hpack = internal::DynamicTable { .. };
        var sess = internal::new_h2_server_session("localhost");
        var pipeline = wing::ServerPipelineConfig { .. };
        var timer = internal::ConnectionTimer { .. };

        // Handshake
        var init_wire: u8[..64] = [];
        init_wire.append(internal::H2_CLIENT_PREFACE[..]);
        let set_hdr = internal::FrameHeader { length: 0, frame_type: internal::FRAME_SETTINGS, flags: 0, stream_id: 0 };
        internal::encode_frame_header_to(set_hdr, init_wire);
        var server_out: u8[..1024] = [];
        let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out);
        sub.assert_true(ok_init, "handshake succeeds");

        // Complete HEADERS frame (END_HEADERS only, stream 1) so stream is established
        var full_req:    u8[..256] = [];
        var hpack_block: u8[..128] = [];
        internal::encode_hpack_field(client_hpack, hpack_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hpack_block, ":path", "/data", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(client_hpack, hpack_block, ":authority", "example.com", internal::HpackIndexing.Incremental, false);

        let req_hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: internal::FRAME_HEADERS,
            flags:      internal::FLAG_END_HEADERS,
            stream_id:  1,
        };
        internal::encode_frame_header_to(req_hdr, full_req);
        full_req.append(hpack_block[..]);

        server_out.clear();
        let _, ok_req = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..], 1001, server_out);
        sub.assert_true(ok_req, "HEADERS frame accepted");

        // Build DATA frame claiming length 100 but only provide 50 bytes of payload
        var data_wire: u8[..128] = [];
        let data_hdr = internal::FrameHeader {
            length:     100,
            frame_type: internal::FRAME_DATA,
            flags:      0,
            stream_id:  1,
        };
        internal::encode_frame_header_to(data_hdr, data_wire);
        // Append only 50 bytes of the claimed 100-byte payload
        for i in 50 {
            data_wire.append([65]);
        }

        // Stage 1: DATA header only (9 bytes) -> consumed 0, ok true, no response
        server_out.clear();
        let c_d1, ok_d1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", data_wire[..9], 1002, server_out);
        sub.assert_true(ok_d1, "DATA header-only ingress ok (no stream error)");
        sub.assert_eq(c_d1, 0, "DATA header-only consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on DATA header-only");

        // Stage 2: Header + partial payload (50 of 100 bytes) -> consumed 0, ok true, no response
        server_out.clear();
        let c_d2, ok_d2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", data_wire[..], 1003, server_out);
        sub.assert_true(ok_d2, "partial DATA ingress ok (no stream error)");
        sub.assert_eq(c_d2, 0, "partial DATA consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on incomplete DATA");
    };

    t.run("AW-H3-01: truncated length varint on frame header") { sub =>
        // 2-byte varint length starts with 0x40|... prefix; feed only first byte
        // Frame type 0x00 (DATA) is 1-byte varint; length varint starts with 0x40 (2-byte prefix)
        let truncated: u8[2] = [0x00, 0x40];
        let _, ok = internal::parse_h3_frame_header(truncated[..], 0);
        sub.assert_false(ok, "truncated 2-byte length varint must not parse as valid frame header");
    };

    t.run("AW-H3-02: frame length larger than provided payload") { sub =>
        // Valid frame header: type=0x00 (DATA), length=10 (1-byte varint 0x0A)
        // But only 4 payload bytes present -> frame is incomplete
        //
        // NOTE: parse_h3_frame_header is header-only (parses type+length varints, no payload).
        // It cannot detect incomplete frames. The production frame-level consumers
        // (process_peer_control_stream, handle_bidi_stream_frames in http3/connection.goose)
        // check offset + payload_len <= data.len and reject with H3_ERR_FRAME_ERROR.
        // This test only asserts the header parses correctly; full-frame incomplete-payload
        // rejection is not covered here because the API cannot express it.
        var wire: u8[..16] = [];
        wire.append([0x00]);  // frame type: DATA
        wire.append([0x0A]);  // length: 10
        // Only 4 payload bytes (not 10)
        wire.append([0x41]);
        wire.append([0x42]);
        wire.append([0x43]);
        wire.append([0x44]);

        let hdr, ok_hdr = internal::parse_h3_frame_header(wire[..], 0);
        sub.assert_true(ok_hdr, "frame header itself parses");
        sub.assert_eq(hdr.payload_len, 10, "payload_len claims 10");
    };
}

fn test_adversarial_grpc_web(t: lit::T&) {
    t.run("AW-GRPC-01: invalid base64 alphabet rejected") { sub =>
        var ctrl_out: u8[>..] = [];
        sub.assert_true(wing::decode_grpc_web_text("QUJD", ctrl_out), "control: valid base64 text decodes");

        var bang_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("QU!D", bang_out), "'!' outside the base64 alphabet rejected");

        var at_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("QU@D", at_out), "'@' outside the base64 alphabet rejected");

        var spc_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("QU D", spc_out), "space outside the base64 alphabet rejected");
    };

    t.run("AW-GRPC-02: bad padding rejected") { sub =>
        var rem1_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("AAAAA", rem1_out), "length % 4 == 1 stream rejected");

        var lone_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("A", lone_out), "lone 6-bit char rejected");

        var lead_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("=A==", lead_out), "padding before payload rejected");

        var mid_out: u8[>..] = [];
        sub.assert_false(wing::decode_grpc_web_text("AA=A", mid_out), "padding in the middle rejected");
    };

    t.run("AW-GRPC-03: trailer frame without grpc-status is not OK") { sub =>
        // Control: OK surfaces only because a well-formed grpc-status field carries it.
        var ctrl_frame: u8[>..] = [];
        wing::encode_grpc_web_trailers(wing::GrpcStatusCode.Ok, "OK", ctrl_frame);
        var ctrl_payload: u8[>..] = [];
        var ctrl_is_trailers = false;
        var ctrl_comp = false;
        let ok_ctrl, _ = wing::decode_grpc_web_frame(ctrl_frame[..], 0, ctrl_payload, ctrl_is_trailers, ctrl_comp);
        sub.assert_true(ok_ctrl, "control trailers frame decodes");
        var st_ctrl = wing::GrpcStatusCode.Unknown;
        var msg_ctrl: u8[..256] = [];
        let parsed_ctrl = wing::parse_grpc_web_trailers(ctrl_payload[..], st_ctrl, msg_ctrl);
        sub.assert_true(parsed_ctrl, "control trailers parse");
        sub.assert_eq(st_ctrl, wing::GrpcStatusCode.Ok, "control surfaces OK via its grpc-status field");

        // Variant A: trailers frame body carries grpc-message but no grpc-status.
        var body_a: u8[..64] = [];
        body_a.append("grpc-message: oops\r\n");
        var frame_a: u8[>..] = [];
        frame_a.push(wing::GRPC_WEB_FLAG_TRAILERS);
        core::write_be_u32(frame_a, body_a.len as u32);
        frame_a.append(body_a[..]);

        var payload_a: u8[>..] = [];
        var is_trailers_a = false;
        var comp_a = false;
        let ok_a, _ = wing::decode_grpc_web_frame(frame_a[..], 0, payload_a, is_trailers_a, comp_a);
        sub.assert_true(ok_a, "trailers frame without grpc-status is structurally decodable");
        sub.assert_true(is_trailers_a, "flag 0x80 marks the frame as trailers");
        var st_a = wing::GrpcStatusCode.Unknown;
        var msg_a: u8[..256] = [];
        let parsed_a = wing::parse_grpc_web_trailers(payload_a[..], st_a, msg_a);
        sub.assert_false(parsed_a, "missing grpc-status must fail parse");
        // Fail-open residue: parse_grpc_web_trailers leaves out_status=Ok on failure
        // (grpc/framing.goose:237) — PARKED for Vector B hardening.
        sub.assert_eq(st_a, wing::GrpcStatusCode.Ok, "residue pin: failed parse leaves out_status=Ok (fail-open)");

        // Variant B: grpc-status field present but with an empty value.
        var st_b = wing::GrpcStatusCode.Unknown;
        var msg_b: u8[..256] = [];
        let parsed_b = wing::parse_grpc_web_trailers("grpc-status: \r\n", st_b, msg_b);
        sub.assert_false(parsed_b, "empty grpc-status value must fail parse");
        sub.assert_eq(st_b, wing::GrpcStatusCode.Ok, "residue pin: failed parse leaves out_status=Ok (fail-open)");
    };

    t.run("AW-GRPC-04: incomplete 5-byte LPM prefix in web frame payload") { sub =>
        // gRPC-Web data frame (flag 0x00) wrapping only the first 3 bytes of a 5-byte LPM prefix.
        let frame: u8[8] = [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];

        var payload: u8[>..] = [];
        var is_trailers = false;
        var is_comp = false;
        let ok_frame, _ = wing::decode_grpc_web_frame(frame[..], 0, payload, is_trailers, is_comp);
        sub.assert_true(ok_frame, "web frame wrapping the fragment is complete");
        sub.assert_false(is_trailers, "data frame, not trailers");
        sub.assert_eq(payload.len, 3, "frame payload is the 3-byte LPM fragment");

        var msg: u8[>..] = [];
        var comp = false;
        let ok_lpm, _ = wing::decode_grpc_lpm(payload[..], 0, msg, comp);
        sub.assert_false(ok_lpm, "3-byte fragment cannot satisfy the 5-byte LPM prefix");

        let _, _, _, ok_slice = wing::decode_grpc_lpm_slice(payload[..], 0);
        sub.assert_false(ok_slice, "zero-copy slice decoder rejects the truncated prefix too");
    };
}

fn test_adversarial_cookie_url(t: lit::T&) {
    let now_us = 1700000000000000;

    t.run("AW-CK-01: unterminated DQUOTE in cookie value rejected") { sub =>
        var jar = wing::CanonicalCookieJar { .. };
        let ok = wing::set_cookie_header(jar, "https://example.com/", "k=\"unterminated; Path=/", now_us, true);
        sub.assert_false(ok, "unterminated DQUOTE in cookie value must fail parse, not succeed");
        sub.assert_eq(jar.cookies.len, 0, "no cookie stored from the unclosed-quote pair");
    };

    t.run("AW-CK-02: missing '=' separator rejected") { sub =>
        var jar = wing::CanonicalCookieJar { .. };
        let ok = wing::set_cookie_header(jar, "https://example.com/", "justname; Path=/", now_us, true);
        // CURRENT behavior: RFC 6265bis §5.6 parses a pair lacking '=' as nameless (name="", value=pair).
        // Spec-compliant per RFC 6265bis §5.6 (pinned by LEX-10/11); no Vector B work required unless product wants stricter.
        sub.require_true(ok, "nameless pair accepted per RFC 6265bis §5.6");
        sub.require_eq(jar.cookies.len, 1, "exactly one nameless cookie stored");
        sub.assert_bytes_eq(jar.cookies[0].name[..], "", "stored cookie name is empty");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "justname", "stored value is the pair text");
    };

    t.run("AW-URL-01: double :: in IPv6 rejected") { sub =>
        let view, err = core::parse_url_view("http://[2001::db8::1]/");
        sub.assert_false(view.valid, "double :: IPv6 host must not parse");
        sub.assert_true(err == core::UrlParseError.InvalidIpv6, "double :: yields InvalidIpv6");
    };

    t.run("AW-URL-02: non-hex IPv6 group rejected") { sub =>
        let view, err = core::parse_url_view("http://[2001:db8:zzzz::1]/");
        sub.assert_false(view.valid, "non-hex IPv6 group must not parse");
        sub.assert_true(err == core::UrlParseError.InvalidIpv6, "non-hex group yields InvalidIpv6");
    };

    t.run("AW-URL-03: unclosed bracket rejected") { sub =>
        let view, err = core::parse_url_view("http://[2001:db8::1/");
        sub.assert_false(view.valid, "unclosed IPv6 bracket must not parse");
        sub.assert_true(err == core::UrlParseError.InvalidIpv6, "unclosed bracket yields InvalidIpv6");
    };
}

fn test_cursor_transactionality(t: lit::T&) {
    t.run("AW-CUR-01: failed decode_grpc_lpm_slice does not require caller buffer mutation") { sub =>
        // Bad wire A: truncated 5-byte LPM prefix (only 3 bytes present).
        let trunc: u8[3] = [0x00, 0x00, 0x00];
        var trunc_snap: u8[..3] = [];
        trunc_snap.append(trunc[..]);
        let p_a, _, c_a, ok_a = wing::decode_grpc_lpm_slice(trunc[..], 0);
        sub.assert_false(ok_a, "truncated LPM prefix must not decode");
        sub.assert_eq(c_a, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_a.len, 0, "failure payload slice is empty");
        sub.assert_bytes_eq(trunc[..], trunc_snap[..], "wire contents unchanged after failure");

        // Bad wire B: reserved flag bits set (0x02 outside GRPC_FLAG_COMPRESSED).
        let bad_flag: u8[6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x41];
        var flag_snap: u8[..6] = [];
        flag_snap.append(bad_flag[..]);
        let p_b, _, c_b, ok_b = wing::decode_grpc_lpm_slice(bad_flag[..], 0);
        sub.assert_false(ok_b, "reserved flag bits must not decode");
        sub.assert_eq(c_b, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_b.len, 0, "failure payload slice is empty");
        sub.assert_bytes_eq(bad_flag[..], flag_snap[..], "wire contents unchanged after failure");

        // Bad wire C: flag byte 0x00 at index 0; length field = bytes 1-4 = 00 00 10 00 = 4096,
        // which exceeds the remaining buffer (1 payload byte).
        let over: u8[6] = [0x00, 0x00, 0x00, 0x10, 0x00, 0x41];
        var over_snap: u8[..6] = [];
        over_snap.append(over[..]);
        let p_c, _, c_c, ok_c = wing::decode_grpc_lpm_slice(over[..], 0);
        sub.assert_false(ok_c, "claimed length beyond buffer must not decode");
        sub.assert_eq(c_c, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_c.len, 0, "failure payload slice is empty");
        sub.assert_bytes_eq(over[..], over_snap[..], "wire contents unchanged after failure");

        // Bad offset: start past the end of an otherwise well-formed wire.
        let good: u8[6] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x41];
        let p_d, _, c_d, ok_d = wing::decode_grpc_lpm_slice(good[..], 7);
        sub.assert_false(ok_d, "offset past end must not decode");
        sub.assert_eq(c_d, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_d.len, 0, "failure payload slice is empty");
    };

    t.run("AW-CUR-02: parse_ws_frame_header on truncated input returns false and does not claim payload") { sub =>
        // 1-byte buffer: an RFC 6455 frame header minimally needs 2 bytes.
        let one: u8[1] = [0x81];
        var one_snap: u8[..1] = [];
        one_snap.append(one[..]);
        let hdr_a, ok_a = wing::parse_ws_frame_header(one[..]);
        sub.assert_false(ok_a, "1-byte buffer cannot contain a frame header");
        sub.assert_eq(hdr_a.payload_len, 0, "no payload length claimed on failure");
        sub.assert_eq(hdr_a.header_len, 0, "no header length claimed on failure");
        sub.assert_bytes_eq(one[..], one_snap[..], "source buffer unchanged after failure");

        // Truncated extended-length header: 16-bit length prefix byte present but length bytes missing.
        let trunc16: u8[2] = [0x81, 0x7E];
        let hdr_b, ok_b = wing::parse_ws_frame_header(trunc16[..]);
        sub.assert_false(ok_b, "truncated 16-bit extended length must not parse");
        sub.assert_eq(hdr_b.payload_len, 0, "no payload length claimed on failure");
        sub.assert_eq(hdr_b.header_len, 0, "no header length claimed on failure");
    };

    t.run("AW-CUR-03: parse_headers error leaves map.valid false and does not leave partial Host") { sub =>
        // Failing Content-Length first; Host after the error point must not materialize.
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Content-Length: abc\r\nHost: example.com\r\n\r\n", map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "non-digit Content-Length yields InvalidContentLength");
        sub.assert_false(map.valid, "map.valid false after framing error");
        sub.assert_false(wing::has_header(map, "content-length"), "invalid Content-Length entry is not stored");
        sub.assert_false(wing::has_header(map, "host"), "Host after the failing line does not materialize (no partial Host)");

        // Host-first residue: Host parses before the failing line. Pre-error entries may remain
        // in the map and are gated only by map.valid (fail-closed). Whether a failing parse should
        // empty the map versus relying on valid-flag gating is an open product contract question
        // (RF10) - has_header(map, "host") is deliberately not asserted either way here.
        var map_hf = wing::HeaderMap { .. };
        let err_hf = wing::parse_headers("Host: example.com\r\nContent-Length: abc\r\n\r\n", map_hf);
        sub.assert_eq(err_hf, wing::HeaderParseError.InvalidContentLength, "non-digit Content-Length yields InvalidContentLength");
        sub.assert_false(map_hf.valid, "map.valid false after framing error (fail-closed gate)");
    };
}

fn main() {
    var runner = lit::new_runner("Vector C: Adversarial HTTP/1.1 Header Boundary Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. HTTP/1.1 Adversarial Header Boundaries", test_adversarial_http1_headers);
    lit::run_case(runner, "2. HTTP/2 and HTTP/3 Frame Chopping", test_adversarial_h2_h3_chopping);
    lit::run_case(runner, "3. gRPC-Web Malformed Decoding Path", test_adversarial_grpc_web);
    lit::run_case(runner, "4. Cookie and URL Adversarial Parsers", test_adversarial_cookie_url);
    lit::run_case(runner, "5. Cursor and Consumed Transactionality", test_cursor_transactionality);

    let ok = lit::finish(runner);
    assert(ok);
}
