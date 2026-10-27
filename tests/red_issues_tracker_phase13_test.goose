// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 13 RED test suite: RFC Protocol Invariants, Payload Truncation Smuggling,
// Boundary Validations, and Safe Resource Limits.
//
// 1. HTTP/2 Content-Length desync, padding bounds & mandatory pseudo-headers (server/h2_multiplexer.goose)
// 2. WebSocket Connection header token parsing & unfragmented frame capacity (realtime/websocket.goose)
// 3. Client Redirect cross-origin Origin leak on 307/308 & fragment capacity (client/redirect.goose)
// 4. Server-Sent Events empty data dispatch & retry integer overflow (realtime/sse.goose)
// 5. Multipart boundary trailing space & parameter truncation smuggling (http/multipart.goose)
// 6. Connection pool TLD wildcard SAN defense & CONNECT response parser desync (net/pool.goose, net/proxy.goose)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. HTTP/2 Server Multiplexer (server/h2_multiplexer.goose, http2/*)
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_rfc9113_invariants(t: core::T&) {
    var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);

    t.run("H2 ingress rejects Content-Length > 0 on HEADERS frame with END_STREAM") { sub =>
        sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(wing::H2_CLIENT_PREFACE[..]);

        // HEADERS frame on stream 1 with END_STREAM set, but Content-Length: 10!
        var hpack_block: u8[>..] = [];
        var dt = wing::new_dynamic_table(4096);
        wing::encode_hpack_field(dt, hpack_block, ":method", "POST", true, false);
        wing::encode_hpack_field(dt, hpack_block, ":scheme", "https", true, false);
        wing::encode_hpack_field(dt, hpack_block, ":path", "/api", true, false);
        wing::encode_hpack_field(dt, hpack_block, "content-length", "10", true, false);

        let flags = wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM;
        let hdr = wing::FrameHeader {
            length: hpack_block.len as u32,
            frame_type: wing::FRAME_HEADERS,
            flags: flags,
            stream_id: 1,
        };
        wing::encode_frame_header_to(hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);

        // Under RFC 9113 §8.1.1, Content-Length mismatch on END_STREAM MUST be rejected
        sub.assert_false(ok, "Content-Length: 10 with 0 DATA bytes must be rejected as protocol error");
    };

    t.run("H2 ingress rejects PADDED frame when pad_len >= frame_payload.len") { sub =>
        sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(wing::H2_CLIENT_PREFACE[..]);

        // PADDED frame with payload length 5, but pad_len byte = 10 (pad_len >= payload_len)
        let hdr = wing::FrameHeader {
            length: 5,
            frame_type: wing::FRAME_DATA,
            flags: wing::FLAG_PADDED,
            stream_id: 1,
        };
        wing::encode_frame_header_to(hdr, wire_in);
        wire_in.push(10); // pad_len byte = 10
        wire_in.push(0); wire_in.push(0); wire_in.push(0); wire_in.push(0);

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Padding length >= frame payload length MUST emit GOAWAY(PROTOCOL_ERROR)");
    };

    t.run("H2 ingress rejects request missing mandatory pseudo-headers") { sub =>
        sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(wing::H2_CLIENT_PREFACE[..]);

        // HEADERS frame missing :path and :scheme
        var hpack_block: u8[>..] = [];
        var dt = wing::new_dynamic_table(4096);
        wing::encode_hpack_field(dt, hpack_block, ":method", "GET", true, false);

        let flags = wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM;
        let hdr = wing::FrameHeader {
            length: hpack_block.len as u32,
            frame_type: wing::FRAME_HEADERS,
            flags: flags,
            stream_id: 1,
        };
        wing::encode_frame_header_to(hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Request missing :scheme and :path MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 2. WebSocket Protocol Invariants (realtime/websocket.goose)
// ----------------------------------------------------------------------------
fn test_websocket_token_and_capacity_invariants(t: core::T&) {
    t.run("ws_upgrade_request rejects Connection header with non-token substring") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "not-an-upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        var resp = wing::new_response();
        let _, ok = wing::ws_upgrade_request(req, resp);
        sub.assert_false(ok, "Connection: not-an-upgrade MUST NOT match 'Upgrade' token");
        sub.assert_eq(resp.status_code, 400, "Response status 400 Bad Request");
    };

    t.run("ws_upgrade_request accepts Upgrade token when multiple Connection headers exist") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "keep-alive");
        req.headers.push(wing::make_header("Connection", "Upgrade"));
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        var resp = wing::new_response();
        let _, ok = wing::ws_upgrade_request(req, resp);
        sub.assert_true(ok, "Upgrade token in second Connection header MUST be recognized");
        sub.assert_eq(resp.status_code, 101, "Response status 101 Switching Protocols");
    };

    t.run("receive rejects unfragmented message exceeding 16KB with MessageTooBig (1009)") { sub =>
        var ws = wing::new_websocket_session(true);
        let no_mask: u8[4] = [0, 0, 0, 0];

        // 20000-byte unfragmented text frame
        var big_payload: u8[>..] = [];
        for i in 20000 { big_payload.push('a'); }

        var wire: u8[>..] = [];
        wing::encode_ws_frame(wire, wing::WS_OPCODE_TEXT, big_payload[..], false, no_mask, true);

        var msg = wing::WsMessage { .. };
        var reply: u8[>..] = [];
        wing::receive(ws, wire[..], msg, reply);

        sub.assert_false(msg.is_valid, "Message exceeding 16KB capacity MUST NOT be marked valid");
        sub.assert_true(ws.is_closed, "WebSocket session MUST be closed on capacity overflow");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_MESSAGE_TOO_BIG, "Close code MUST be 1009 Message Too Big");
    };
}

// ----------------------------------------------------------------------------
// 3. Client Redirect Engine (client/redirect.goose)
// ----------------------------------------------------------------------------
fn test_client_redirect_origin_and_fragment_safety(t: core::T&) {
    t.run("Cross-origin 307 redirect MUST set Origin to null to prevent leaking internal origin") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Origin", "https://internal.corp.example.com"));
        headers.push(wing::make_header("Content-Type", "application/json"));

        var redir = wing::RedirectInfo {
            status_code: 307,
            is_cross_origin: true,
            clear_body: false, // 307 retains POST body!
            ..
        };

        wing::sanitize_headers_on_redirect(headers, redir, false, false, false);

        let origin_idx = wing::find_header_index(headers[..], "Origin");
        sub.assert_ge(origin_idx, 0, "Origin header present");
        sub.assert_bytes_eq(headers[origin_idx].value[..], "null", "Origin on cross-origin 307 MUST be 'null'");
    };

    t.run("inherit_target_fragment does not crash when combined length exceeds 2048") { sub =>
        var long_target: u8[>..] = [];
        long_target.append("https://target.com/");
        for i in 2040 { long_target.push('x'); }

        // Must not crash or panic with capacity exceeded
        let info = wing::compute_redirect_info(
            "GET",
            302,
            "https://example.com/base#very-long-fragment",
            long_target[..],
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin,
            "",
            false,
            true,
        );
        sub.assert_true(info.error == wing::RedirectError.None || info.error == wing::RedirectError.InvalidLocationUrl, "Handled safely without crash");
    };
}

// ----------------------------------------------------------------------------
// 4. Server-Sent Events (realtime/sse.goose)
// ----------------------------------------------------------------------------
fn test_sse_w3c_spec_invariants(t: core::T&) {
    t.run("W3C EventSource §9.2.6: Event without data field MUST NOT dispatch") { sub =>
        var parser = wing::new_sse_parser();
        var events: wing::SseEvent[..16] = [];

        // Stream with event: ping but NO data: line, followed by empty line
        wing::sse_feed(parser, "event: ping\n\n", events);

        sub.assert_eq(events.len, 0, "Event without data line MUST NOT be dispatched per W3C Section 9.2.6");
    };

    t.run("SSE retry integer parsing must not overflow into tight reconnect loop") { sub =>
        var parser = wing::new_sse_parser();
        var events: wing::SseEvent[..16] = [];

        // 20-digit number exceeding u32::MAX
        wing::sse_feed(parser, "retry: 99999999999999999999\ndata: ok\n\n", events);

        sub.assert_gt(parser.retry_ms, 0, "retry_ms must remain positive and saturated");
        sub.assert_eq(parser.retry_ms, 0xFFFFFFFF, "retry_ms saturated to u32::MAX on overflow");
    };

    t.run("sse_format_event rejects or strips CRLF injection in event_type and id") { sub =>
        var out: u8[>..] = [];
        wing::sse_format_event(out, "custom\r\ndata: injected", "hello", "id1\r\nevil: true");

        sub.assert_false(core::contains(out[..], "\r"), "CRLF injection in event_type/id must not produce raw CR");
        sub.assert_false(core::contains(out[..], "data: injected"), "Injected data line in event_type must not appear");
    };
}

// ----------------------------------------------------------------------------
// 5. Multipart Form-Data (http/multipart.goose)
// ----------------------------------------------------------------------------
fn test_multipart_boundary_and_smuggling_invariants(t: core::T&) {
    t.run("RFC 2046 §5.1.1: Boundary ending in space is strictly invalid") { sub =>
        let valid_space = wing::validate_boundary_string("valid-boundary ");
        sub.assert_false(valid_space, "Boundary with trailing space MUST be rejected per RFC 2046 §5.1.1");
    };

    t.run("Multipart part with field name > 64B MUST NOT be silently truncated") { sub =>
        var long_name: u8[>..] = [];
        for i in 65 { long_name.push('a'); }

        var body: u8[>..] = [];
        body.append("--myboundary\r\nContent-Disposition: form-data; name=\"");
        body.append(long_name[..]);
        body.append("\"\r\n\r\nvalue\r\n--myboundary--\r\n");

        let msg, err = wing::parse_multipart(body[..], "myboundary");
        // Parameter name > 64B must return InvalidPartHeaders and not truncate to 64 'a's
        sub.assert_false(wing::is_ok(err), "Field name > 64B must be rejected rather than silently truncated");
        sub.assert_false(msg.valid, "Message valid flag must be false");
    };
}

// ----------------------------------------------------------------------------
// 6. Connection Pool & Proxies (net/pool.goose, net/proxy.goose)
// ----------------------------------------------------------------------------
fn test_pool_and_proxy_san_invariants(t: core::T&) {
    t.run("matches_san_pattern rejects TLD wildcard *.com") { sub =>
        let matches_tld = wing::matches_san_pattern("*.com", "example.com");
        sub.assert_false(matches_tld, "*.com wildcard MUST NOT match apex domain (RFC 6125 §6.4.3)");
    };

    t.run("matches_san_pattern rejects candidate hostname with literal wildcard") { sub =>
        let matches_wild = wing::matches_san_pattern("*.example.com", "*.example.com");
        sub.assert_false(matches_wild, "Candidate hostname containing literal '*' MUST NOT match");
    };

    t.run("verify_connect_tunnel_response rejects non-HTTP or 4-digit status codes") { sub =>
        let err1 = wing::verify_connect_tunnel_response("HTTP/1.1 2000 OK\r\n\r\n");
        sub.assert_true(err1 == wing::ConnectTunnelError.InvalidStatusLine, "Status code '2000' must be InvalidStatusLine");

        let err2 = wing::verify_connect_tunnel_response("UNKNOWN 200 OK\r\n\r\n");
        sub.assert_true(err2 == wing::ConnectTunnelError.InvalidStatusLine, "Non-HTTP protocol must be InvalidStatusLine");
    };
}

// ----------------------------------------------------------------------------
// Main Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("RED Suite Phase 13: Protocol Invariants & Safe Limits", core::Verbosity.Verbose);

    core::run_case(runner, "1. H2 multiplexer RFC 9113 invariants (server/h2_multiplexer.goose)", test_h2_multiplexer_rfc9113_invariants);
    core::run_case(runner, "2. WebSocket token & capacity invariants (realtime/websocket.goose)", test_websocket_token_and_capacity_invariants);
    core::run_case(runner, "3. Client Redirect origin & fragment safety (client/redirect.goose)", test_client_redirect_origin_and_fragment_safety);
    core::run_case(runner, "4. Server-Sent Events W3C spec invariants (realtime/sse.goose)", test_sse_w3c_spec_invariants);
    core::run_case(runner, "5. Multipart boundary & smuggling invariants (http/multipart.goose)", test_multipart_boundary_and_smuggling_invariants);
    core::run_case(runner, "6. Pool & Proxy SAN invariants (net/pool.goose, net/proxy.goose)", test_pool_and_proxy_san_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
