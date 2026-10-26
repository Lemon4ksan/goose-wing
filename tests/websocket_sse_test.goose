// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite for WebSocket (RFC 6455 / RFC 8441), HTTP/3 PRIORITY_UPDATE (RFC 9218)
// and Server-Sent Events (W3C EventSource).
import std;
import core from "..";
import wing from "..";

fn test_websocket_framing_and_handshake(t: core::T&) {
    t.run("1. RFC 6455 Section 1.3 Handshake Vector Verification") { sub =>
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        var accept_key: u8[>..] = [];
        wing::compute_websocket_accept(client_key, accept_key);

        sub.assert_bytes_eq(
            accept_key[..],
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "RFC 6455 Section 1.3 Sec-WebSocket-Accept key derivation matches standard vector"
        );
        sub.assert_true(wing::validate_websocket_accept(client_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "Validation succeeds");
        sub.assert_false(wing::validate_websocket_accept(client_key, "invalid_accept_key="), "Tampered accept key rejected");

        // Nonce generator
        let test_nonce: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var out_key: u8[>..] = [];
        wing::generate_websocket_key(test_nonce, out_key);
        sub.assert_eq(out_key.len, 24, "Client key is 24 base64 characters");
    };

    t.run("2. RFC 6455 In-Place 64-Bit Unrolled Masking") { sub =>
        let mask_key: u8[4] = [0x37, 0xfa, 0x21, 0x3d];
        var payload: u8[>..] = [];
        payload.append("Hello, WebSocket Zero-Allocation World! This is a longer string to test 64-bit unrolling.");

        var original: u8[>..] = [];
        original.append(payload[..]);

        // Mask
        wing::mask_websocket_payload(payload[..], mask_key);
        sub.assert_false(payload[..] == original[..], "Masked payload differs from original plaintext");

        // Unmask (symmetric XOR)
        wing::mask_websocket_payload(payload[..], mask_key);
        sub.assert_bytes_eq(payload[..], original[..], "Unmasking perfectly restores original plaintext");
    };

    t.run("3. Small, Medium (16-bit) and Large (64-bit) Frame Headers") { sub =>
        // Small frame (<= 125 bytes)
        let hdr_small = wing::WsFrameHeader {
            fin: true,
            opcode: wing::WS_OPCODE_TEXT,
            masked: true,
            mask_key: [0x12, 0x34, 0x56, 0x78],
            payload_len: 42,
            ..
        };
        var buf_small: u8[>..] = [];
        hdr_small.encode(buf_small);
        sub.assert_eq(buf_small.len, 6, "Small frame header length is 2 + 4 = 6 bytes (UFCS)");

        let parsed_small, ok_s = wing::parse_ws_frame_header(buf_small[..]);
        sub.assert_true(ok_s, "Small frame header parsed");
        sub.assert_eq(parsed_small.payload_len, 42, "Small payload length 42");
        sub.assert_true(parsed_small.masked, "Masked bit set");
        sub.assert_eq(parsed_small.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");

        // Medium frame (126..65535 bytes)
        let hdr_med = wing::WsFrameHeader {
            fin: true,
            opcode: wing::WS_OPCODE_BINARY,
            masked: false,
            payload_len: 1000,
            ..
        };
        var buf_med: u8[>..] = [];
        hdr_med.encode(buf_med);
        sub.assert_eq(buf_med.len, 4, "Medium unmasked frame header length is 2 + 2 = 4 bytes");

        let parsed_med, ok_m = wing::parse_ws_frame_header(buf_med[..]);
        sub.assert_true(ok_m, "Medium frame header parsed");
        sub.assert_eq(parsed_med.payload_len, 1000, "Medium payload length 1000");

        // Large frame (> 65535 bytes)
        let hdr_lg = wing::WsFrameHeader {
            fin: true,
            opcode: wing::WS_OPCODE_BINARY,
            masked: false,
            payload_len: 100000,
            ..
        };
        var buf_lg: u8[>..] = [];
        hdr_lg.encode(buf_lg);
        sub.assert_eq(buf_lg.len, 10, "Large frame header length is 2 + 8 = 10 bytes");

        let parsed_lg, ok_l = wing::parse_ws_frame_header(buf_lg[..]);
        sub.assert_true(ok_l, "Large frame header parsed");
        sub.assert_eq(parsed_lg.payload_len, 100000, "Large payload length 100000");
    };

    t.run("4. Control Frame Invariants & Close Payload") { sub =>
        // Control frames MUST NOT be fragmented (RFC 6455 Section 5.5)
        let frag_ping: u8[2] = [0x09, 0x00]; // FIN = 0, Opcode = 9 (Ping)
        let _, ok_frag = wing::parse_ws_frame_header(frag_ping[..]);
        sub.assert_false(ok_frag, "Fragmented control frame (FIN=0) must be rejected");

        // Control frames MUST NOT have payload > 125
        let large_ping: u8[4] = [0x89, 126, 0x00, 0x80]; // Ping with 128 bytes
        let _, ok_lg_ping = wing::parse_ws_frame_header(large_ping[..]);
        sub.assert_false(ok_lg_ping, "Control frame with payload > 125 must be rejected");

        // Close payload codec
        var close_buf: u8[>..] = [];
        wing::encode_close_payload(close_buf, wing::WS_STATUS_NORMAL, "goodbye");
        sub.assert_eq(close_buf.len, 2 + 7, "2 status bytes + 7 reason bytes");

        let code, reason, ok_close = wing::parse_close_payload(close_buf[..]);
        sub.assert_true(ok_close, "Close payload parsed successfully");
        sub.assert_eq(code, wing::WS_STATUS_NORMAL, "Status is 1000 Normal");
        sub.assert_bytes_eq(reason, "goodbye", "Reason matches");
    };

    t.run("5. Full Frame Serialization & RFC 6455 Roundtrip") { sub =>
        let mask: u8[4] = [0xaa, 0xbb, 0xcc, 0xdd];
        var wire: u8[>..] = [];
        wing::encode_ws_frame(wire, wing::WS_OPCODE_TEXT, "Wing Engine WebSocket", true, mask, true);

        let hdr, ok = wing::parse_ws_frame_header(wire[..]);
        sub.assert_true(ok, "Parse frame header from serialized wire bytes");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_TEXT, "Text opcode");
        sub.assert_true(hdr.masked, "Client frame masked");

        var payload_copy: u8[>..] = [];
        let p_start = hdr.header_len as i64;
        payload_copy.append(wire[p_start..]);
        wing::mask_websocket_payload(payload_copy[..], hdr.mask_key);
        sub.assert_bytes_eq(payload_copy[..], "Wing Engine WebSocket", "De-masked payload matches original");
    };

    t.run("6. WebSocketSession High-Level Lifecycle") { sub =>
        var session = wing::new_websocket_session(true);
        session.subprotocol.append("chat.v1");

        var req: u8[>..] = [];
        session.build_handshake_request("example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", req);
        sub.assert_true(req.len > 0, "Handshake request created via UFCS");

        var text_frame: u8[>..] = [];
        wing::send_text(session, "hello server", text_frame);
        sub.assert_true(text_frame.len > 0, "Text frame generated");

        var ping_frame: u8[>..] = [];
        wing::send_ping(session, "heartbeat", ping_frame);
        sub.assert_true(ping_frame.len > 0, "Ping frame generated");

        var close_frame: u8[>..] = [];
        wing::close(session, wing::WS_STATUS_NORMAL, "goodbye", close_frame);
        sub.assert_true(session.is_closed, "Session marked closed");
        sub.assert_eq(session.close_code, wing::WS_STATUS_NORMAL, "Close code set");
    };

    t.run("7. Aoni-Style Automated Client WebSocket Upgrade & receive Engine") { sub =>
        var client = wing::new_client();
        wing::add_mock_websocket(client, "https://stream.example.com/ws", "chat.v1");

        var ws_sess, resp, err = client.ws("wss://stream.example.com/ws") { req =>
            req.bearer("token123");
            req.set_header("Sec-WebSocket-Protocol", "chat.v1");
        };

        sub.assert_true(err.ok(), "Client ws upgrade succeeded");
        sub.assert_eq(resp.status_code, 101, "Response status 101 Switching Protocols");
        sub.assert_bytes_eq(ws_sess.subprotocol[..], "chat.v1", "Subprotocol negotiated");

        // Test automatic receive on incoming Ping
        var incoming_ping: u8[>..] = [];
        let no_mask: u8[4] = [0, 0, 0, 0];
        wing::encode_ws_frame(incoming_ping, wing::WS_OPCODE_PING, "ping-payload", false, no_mask, true);

        var msg = wing::WsMessage { .. };
        var pong_reply: u8[>..] = [];
        let handled_ping = ws_sess.receive(incoming_ping[..], msg, pong_reply);
        sub.assert_true(handled_ping, "receive processed ping frame");
        sub.assert_eq(msg.opcode, wing::WS_OPCODE_PING, "Message opcode is PING");
        sub.assert_true(pong_reply.len > 0, "Automatic Pong response generated into reply buffer");

        // Verify that the reply is a valid Pong frame
        let pong_hdr, ok_pong = wing::parse_ws_frame_header(pong_reply[..]);
        sub.assert_true(ok_pong, "Parsed auto-pong frame header");
        sub.assert_eq(pong_hdr.opcode, wing::WS_OPCODE_PONG, "Opcode in auto-reply is PONG");

        // Server-side upgrade test with complex Connection header
        var server_req = wing::new_request("GET", "https://example.com/ws");
        server_req.set_header("Upgrade", "websocket");
        server_req.set_header("Connection", "keep-alive, Upgrade");
        server_req.set_header("Sec-WebSocket-Version", "13");
        server_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        var server_resp = wing::new_response();
        let s_ws, ok_s = wing::ws_upgrade_request(server_req, server_resp, "chat.v1");
        sub.assert_true(ok_s, "Server upgrade succeeded");
        sub.assert_eq(server_resp.status_code, 101, "Server status 101");
        sub.assert_bytes_eq(server_resp.header("Sec-WebSocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "Server accept matches RFC 6455");
        sub.assert_false(s_ws.is_client, "Server session is_client is false");

        // Negative tests: wrong method
        var bad_meth_req = wing::new_request("POST", "https://example.com/ws");
        var bad_resp = wing::new_response();
        let _, ok_bad_m = wing::ws_upgrade_request(bad_meth_req, bad_resp);
        sub.assert_false(ok_bad_m, "POST upgrade rejected");
        sub.assert_eq(bad_resp.status_code, 405, "Status 405 Method Not Allowed");

        // Negative tests: wrong version
        var bad_ver_req = wing::new_request("GET", "https://example.com/ws");
        bad_ver_req.set_header("Upgrade", "websocket");
        bad_ver_req.set_header("Connection", "Upgrade");
        bad_ver_req.set_header("Sec-WebSocket-Version", "12");
        bad_ver_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        bad_resp = wing::new_response();
        let _, ok_bad_v = wing::ws_upgrade_request(bad_ver_req, bad_resp);
        sub.assert_false(ok_bad_v, "WebSocket Version 12 rejected");
        sub.assert_eq(bad_resp.status_code, 426, "Status 426 Upgrade Required");
        sub.assert_bytes_eq(bad_resp.header("Sec-WebSocket-Version"), "13", "Required version 13 returned");
    };

    t.run("8. Multi-Frame Fragmented Message Assembly & Interleaved Control Frames") { sub =>
        var ws = wing::new_websocket_session(true); // client session
        let no_mask: u8[4] = [0, 0, 0, 0];

        // Fragment 1: TEXT with FIN=0
        var f1_wire: u8[..128] = [];
        wing::encode_ws_frame(f1_wire, wing::WS_OPCODE_TEXT, "Hello, ", false, no_mask, false);

        var msg1 = wing::WsMessage { .. };
        var reply1: u8[..128] = [];
        let ok1 = wing::receive(ws, f1_wire[..], msg1, reply1);
        sub.assert_true(ok1, "receive accepted initial fragment");
        sub.assert_false(msg1.is_valid, "Message not complete on initial fragment");

        // Interleaved Control Frame: PING with FIN=1 during fragmentation (RFC 6455 §5.4)
        var ping_wire: u8[..128] = [];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "mid-stream", false, no_mask, true);

        var ping_msg = wing::WsMessage { .. };
        var ping_reply: u8[..128] = [];
        let ok_p = wing::receive(ws, ping_wire[..], ping_msg, ping_reply);
        sub.assert_true(ok_p, "receive accepted interleaved PING");
        sub.assert_true(ping_msg.is_valid, "Ping message was delivered");
        sub.assert_eq(ping_msg.opcode, wing::WS_OPCODE_PING, "Ping opcode delivered");
        sub.assert_gt(ping_reply.len, 0, "Pong response generated for interleaved ping");

        // Fragment 2: CONTINUATION with FIN=1
        var f2_wire: u8[..128] = [];
        wing::encode_ws_frame(f2_wire, wing::WS_OPCODE_CONTINUATION, "World!", false, no_mask, true);

        var msg2 = wing::WsMessage { .. };
        var reply2: u8[..128] = [];
        let ok2 = wing::receive(ws, f2_wire[..], msg2, reply2);
        sub.assert_true(ok2, "receive accepted terminal CONTINUATION fragment");
        sub.assert_true(msg2.is_valid, "Message is valid upon terminal fragment");
        sub.assert_eq(msg2.opcode, wing::WS_OPCODE_TEXT, "Assembled message preserved original opcode (TEXT)");
        sub.assert_bytes_eq(msg2.data[..], "Hello, World!", "Assembled payload matches combined fragments");
    };

    t.run("9. Autobahn UTF-8 Strict Validation & Anomaly Rejection") { sub =>
        // 9.1 Invalid UTF-8 sequence in text frame (RFC 6455 §5.6, Autobahn Case 6.x)
        var ws1 = wing::new_websocket_session(true);
        let no_mask: u8[4] = [0, 0, 0, 0];

        var bad_text_wire: u8[..128] = [];
        let invalid_utf8: u8[4] = [0xCE, 0xBA, 0xE1, 0x00]; // 0xE1 followed by 0x00 is invalid UTF-8
        wing::encode_ws_frame(bad_text_wire, wing::WS_OPCODE_TEXT, invalid_utf8[..], false, no_mask, true);

        var msg1 = wing::WsMessage { .. };
        var reply1: u8[..128] = [];
        wing::receive(ws1, bad_text_wire[..], msg1, reply1);

        sub.assert_false(msg1.is_valid, "Invalid UTF-8 text rejected");
        sub.assert_true(ws1.is_closed, "Connection closed on invalid UTF-8");
        sub.assert_eq(ws1.close_code, wing::WS_STATUS_INVALID_PAYLOAD, "Close code 1007 Invalid Payload");

        // 9.2 Unexpected CONTINUATION without initial fragment
        var ws2 = wing::new_websocket_session(true);
        var unexpected_cont: u8[..128] = [];
        wing::encode_ws_frame(unexpected_cont, wing::WS_OPCODE_CONTINUATION, "orphan", false, no_mask, true);

        var msg2 = wing::WsMessage { .. };
        var reply2: u8[..128] = [];
        wing::receive(ws2, unexpected_cont[..], msg2, reply2);

        sub.assert_false(msg2.is_valid, "Orphan continuation rejected");
        sub.assert_true(ws2.is_closed, "Connection closed on protocol error");
        sub.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code 1002 Protocol Error");

        // 9.3 Interleaved data frame during fragmentation
        var ws3 = wing::new_websocket_session(true);
        var frag_start: u8[..128] = [];
        wing::encode_ws_frame(frag_start, wing::WS_OPCODE_TEXT, "part1", false, no_mask, false);
        var msg3 = wing::WsMessage { .. };
        var reply3: u8[..128] = [];
        wing::receive(ws3, frag_start[..], msg3, reply3);

        // Next frame is another TEXT frame instead of CONTINUATION
        var bad_interleave: u8[..128] = [];
        wing::encode_ws_frame(bad_interleave, wing::WS_OPCODE_BINARY, "binary-data", false, no_mask, true);
        wing::receive(ws3, bad_interleave[..], msg3, reply3);

        sub.assert_false(msg3.is_valid, "Interleaved data frame rejected");
        sub.assert_true(ws3.is_closed, "Connection closed on interleaving error");
        sub.assert_eq(ws3.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code 1002 Protocol Error");
    };
}

fn test_http3_priority_update(t: core::T&) {
    t.run("1. HTTP/3 PRIORITY_UPDATE Frame Codec (RFC 9218 Section 7.2)") { sub =>
        let prio = wing::PriorityParam { urgency: 1, incremental: true };
        var wire: u8[>..] = [];
        sub.assert_true(wing::encode_h3_priority_update_request(wire, 8, prio), "encode H3 priority update request");

        let hdr, ok_hdr = wing::parse_h3_frame_header(wire[..], 0);
        sub.assert_true(ok_hdr, "parse H3 frame header");
        sub.assert_eq(hdr.frame_type, wing::H3_FRAME_PRIORITY_UPDATE_REQUEST, "Frame type is 0xF0700");

        let h3_payload_start = hdr.header_len as i64;
        let payload = wire[h3_payload_start..];
        let stream_id, parsed_prio, ok_prio = wing::parse_h3_priority_update_request(payload);
        sub.assert_true(ok_prio, "parse H3 priority update payload");
        sub.assert_eq(stream_id, 8, "Prioritized stream ID is 8");
        sub.assert_eq(parsed_prio.urgency as i64, 1, "Urgency is 1");
        sub.assert_true(parsed_prio.incremental, "Incremental is true");

        // Push stream priority update
        var push_wire: u8[>..] = [];
        sub.assert_true(wing::encode_h3_priority_update_push(push_wire, 42, prio), "encode H3 priority update push");
        let push_hdr, ok_push_hdr = wing::parse_h3_frame_header(push_wire[..], 0);
        sub.assert_true(ok_push_hdr, "parse push header");
        sub.assert_eq(push_hdr.frame_type, wing::H3_FRAME_PRIORITY_UPDATE_PUSH, "Frame type is 0xF0701");

        let push_start = push_hdr.header_len as i64;
        let push_id, parsed_push_prio, ok_push = wing::parse_h3_priority_update_push(push_wire[push_start..]);
        sub.assert_true(ok_push, "parse push payload");
        sub.assert_eq(push_id, 42, "Push ID is 42");
        sub.assert_eq(parsed_push_prio.urgency as i64, 1, "Push urgency is 1");
    };
}

fn test_server_sent_events(t: core::T&) {
    t.run("1. W3C EventSource Standard Streaming Parsing") { sub =>
        let stream_data = "data: first event\n\nevent: custom\ndata: second event line 1\ndata: second event line 2\nid: 42\nretry: 5000\n\n";

        var parser = wing::new_sse_parser();
        var events: wing::SseEvent[..10] = [];

        wing::sse_feed(parser, stream_data, events);

        sub.assert_eq(events.len, 2, "2 events dispatched from stream");

        // Event 1
        sub.assert_bytes_eq(events[0].event[..], "message", "Default event type is 'message'");
        sub.assert_bytes_eq(events[0].data[..], "first event", "Event 1 data");
        sub.assert_bytes_eq(events[0].id[..], "", "Event 1 has no id");

        // Event 2 (multi-line data, named event, id, retry)
        sub.assert_bytes_eq(events[1].event[..], "custom", "Event 2 type is 'custom'");
        sub.assert_bytes_eq(events[1].data[..], "second event line 1\nsecond event line 2", "Multi-line data joined by newline");
        sub.assert_bytes_eq(events[1].id[..], "42", "Event 2 id is 42");
        sub.assert_eq(events[1].retry_ms as i64, 5000, "Retry ms is 5000");
    };

    t.run("2. SSE Comment Lines and Keepalive Filtering") { sub =>
        let stream = ": this is a comment\n: keepalive ping\ndata: real data\n\n: another comment\n";
        var parser = wing::new_sse_parser();
        var events: wing::SseEvent[..10] = [];

        wing::sse_feed(parser, stream, events);
        sub.assert_eq(events.len, 1, "Only 1 event dispatched, comments ignored");
        sub.assert_bytes_eq(events[0].data[..], "real data", "Data content");
    };

    t.run("3. CRLF and CR Line Ending Normalization") { sub =>
        let stream_crlf = "data: hello\r\n\r\ndata: world\r\r";
        var parser = wing::new_sse_parser();
        var events: wing::SseEvent[..10] = [];

        wing::sse_feed(parser, stream_crlf, events);
        sub.assert_eq(events.len, 2, "2 events parsed across CRLF and CR boundaries");
        sub.assert_bytes_eq(events[0].data[..], "hello", "Event 0 data");
        sub.assert_bytes_eq(events[1].data[..], "world", "Event 1 data");
    };

    t.run("4. SSE Serializer and Wire Formatting") { sub =>
        var out: u8[>..] = [];
        wing::sse_format_event(out, "update", "line1\nline2", "id-99", 2500);

        let expected = "retry: 2500\nid: id-99\nevent: update\ndata: line1\ndata: line2\n\n";
        sub.assert_bytes_eq(out[..], expected, "SSE serialized event matches expected format");

        // Parse back through parser
        var parser = wing::new_sse_parser();
        var events: wing::SseEvent[..10] = [];
        wing::sse_feed(parser, out[..], events);
        sub.assert_eq(events.len, 1, "Roundtrip parsed 1 event");
        sub.assert_bytes_eq(events[0].event[..], "update", "Event type roundtrip");
        sub.assert_bytes_eq(events[0].data[..], "line1\nline2", "Multi-line data roundtrip");
        sub.assert_bytes_eq(events[0].id[..], "id-99", "Event ID roundtrip");
        sub.assert_eq(events[0].retry_ms as i64, 2500, "Retry ms roundtrip");
    };

    t.run("5. SseSubscription Ergonomics and Header Generation") { sub =>
        var subscr = wing::new_sse_subscription("https://api.example.com/stream");
        subscr.parser.last_event_id.append("evt-1234");

        var req: u8[>..] = [];
        wing::sse_build_request_headers(subscr, "api.example.com", "/stream", req);

        sub.assert_true(req.len > 0, "SSE request headers created");

        var events: wing::SseEvent[..5] = [];
        subscr.consume( "data: chunked message\n\n", events);
        sub.assert_eq(events.len, 1, "Consumed 1 event via SseSubscription");
        sub.assert_bytes_eq(events[0].data[..], "chunked message", "Event content matches");
    };

    t.run("6. Aoni-Style Automated Client SSE Subscription") { sub =>
        var client = wing::new_client();
        wing::add_mock_sse(client, "https://api.example.com/events", "event: tick\nid: 1\ndata: {\"val\":100}\n\n");

        var sse_sub, resp, err = client.sse("https://api.example.com/events") { req =>
            req.bearer("token123");
        };

        sub.assert_true(err.ok(), "Client SSE connect succeeded");
        sub.assert_eq(resp.status_code, 200, "Response status 200 OK");
        sub.assert_true(sse_sub.connected, "Subscription marked connected");

        var events: wing::SseEvent[..5] = [];
        sse_sub.consume(resp.body[..], events);
        sub.assert_eq(events.len, 1, "Consumed 1 event from mock SSE stream");
        sub.assert_bytes_eq(events[0].event[..], "tick", "Event name is tick");
        sub.assert_bytes_eq(events[0].data[..], "{\"val\":100}", "Data payload matches");
        sub.assert_bytes_eq(events[0].id[..], "1", "Event ID matches");

        // Server-side response initialization
        var s_resp = wing::new_response();
        wing::init_response(s_resp);
        sub.assert_eq(s_resp.status_code, 200, "Server SSE status 200");
        sub.assert_bytes_eq(wing::header(s_resp, "Content-Type"), "text/event-stream", "Content-Type text/event-stream");
    };
}

fn main() {
    var runner = core::new_runner("WebSocket, SSE & H3 Extensible Priority Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. WebSocket (RFC 6455 & RFC 8441) Framing and Handshake", test_websocket_framing_and_handshake);
    core::run_case(runner, "2. HTTP/3 PRIORITY_UPDATE (RFC 9218) Frame Codec", test_http3_priority_update);
    core::run_case(runner, "3. Server-Sent Events (SSE / W3C EventSource) Engine", test_server_sent_events);

    let ok = core::finish(runner);
    assert(ok);
}
