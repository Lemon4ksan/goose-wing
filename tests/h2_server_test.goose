// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/h2_server_test.goose
// Verification test suite for HTTP/2 Server Frame Multiplexer (RFC 9113 & RFC 7541).
import std;
import core from "..";
import wing from "..";

// Helper to encode a client request HEADERS frame
fn encode_client_headers<B>(
    dt: wing::DynamicTable&,
    stream_id: u32,
    method: const u8[:],
    path: const u8[:],
    authority: const u8[:],
    end_stream: bool,
    out: B&
) {
    var hdr_block: u8[>..] = [];
    wing::encode_hpack_field(dt, hdr_block, ":method", method, true, false);
    wing::encode_hpack_field(dt, hdr_block, ":path", path, true, false);
    wing::encode_hpack_field(dt, hdr_block, ":scheme", "https", true, false);
    wing::encode_hpack_field(dt, hdr_block, ":authority", authority, true, false);

    var flags: u8 = wing::FLAG_END_HEADERS;
    if end_stream {
        flags |= wing::FLAG_END_STREAM;
    }

    let hdr = wing::FrameHeader {
        length: hdr_block.len as u32,
        frame_type: wing::FRAME_HEADERS,
        flags: flags,
        stream_id: stream_id,
    };
    wing::encode_frame_header_to(hdr, out);
    out.append(hdr_block[..]);
}

// Helper to encode a client DATA frame
fn encode_client_data<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) {
    let flags: u8 = if end_stream { wing::FLAG_END_STREAM } else { 0 };
    let hdr = wing::FrameHeader {
        length: payload.len as u32,
        frame_type: wing::FRAME_DATA,
        flags: flags,
        stream_id: stream_id,
    };
    wing::encode_frame_header_to(hdr, out);
    out.append(payload);
}

// ============================================================================
// 1. Connection Preface, Handshake & Settings Negotiation
// ============================================================================
fn test_h2_handshake_and_settings(t: core::T&) {
    t.run("H2-01: Preface & Initial Server SETTINGS emission") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var out_wire: u8[..512] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wing::H2_CLIENT_PREFACE[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on preface");
        sub.assert_eq(consumed, 24, "Consumed 24 bytes of client preface");
        sub.assert_true(sess.preface_handled, "preface_handled flag is true");
        sub.assert_true(sess.server_settings_sent, "server_settings_sent flag is true");

        // Server must emit SETTINGS frame (type 0x04, length 24, stream 0)
        sub.assert_ge(out_wire.len, 9, "Output has frame header");
        let f_hdr, err_f = wing::parse_frame_header(out_wire[..9]);
        sub.assert_eq(err_f, wing::ERR_NO_ERROR, "Decoded frame header");
        sub.assert_eq(f_hdr.frame_type, wing::FRAME_SETTINGS, "Frame is SETTINGS");
        sub.assert_eq(f_hdr.stream_id, 0, "SETTINGS on stream 0");
        sub.assert_eq(f_hdr.length, 24, "SETTINGS payload is 24 bytes (4 settings)");
    };

    t.run("H2-02: Client SETTINGS ACK & PING ACK") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Prepend preface
        var wire: u8[..512] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Client SETTINGS (empty)
        let s_hdr = wing::FrameHeader {
            length: 0,
            frame_type: wing::FRAME_SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        wing::encode_frame_header_to(s_hdr, wire);

        // Client PING with 8-byte opaque data
        let p_hdr = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        wing::encode_frame_header_to(p_hdr, wire);
        let ping_data: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        for b in ping_data { wire.push(b); }

        var out_wire: u8[..512] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on preface + settings + ping");
        sub.assert_eq(consumed, wire.len, "Consumed full wire");

        // Inspect emitted frames:
        // Frame 1: Server SETTINGS (9 header + 24 payload = 33)
        // Frame 2: Server SETTINGS ACK (9 header + 0 payload = 9)
        // Frame 3: Server PING ACK (9 header + 8 payload = 17)
        sub.assert_ge(out_wire.len, 33 + 9 + 17, "Output has all 3 response frames");

        // Check Frame 2 (SETTINGS ACK)
        let f2_hdr, _ = wing::parse_frame_header(out_wire[33 .. 42]);
        sub.assert_eq(f2_hdr.frame_type, wing::FRAME_SETTINGS, "Frame 2 is SETTINGS");
        sub.assert_true((f2_hdr.flags & wing::FLAG_ACK) != 0, "Frame 2 has FLAG_ACK");

        // Check Frame 3 (PING ACK)
        let f3_hdr, _ = wing::parse_frame_header(out_wire[42 .. 51]);
        sub.assert_eq(f3_hdr.frame_type, wing::FRAME_PING, "Frame 3 is PING");
        sub.assert_true((f3_hdr.flags & wing::FLAG_ACK) != 0, "Frame 3 has FLAG_ACK");
        let ping_echo = out_wire[51 .. 59];
        sub.assert_eq(ping_echo[0], 0x11, "PING opaque byte 0 matched");
        sub.assert_eq(ping_echo[7], 0x88, "PING opaque byte 7 matched");
    };

    t.run("H2-02b: Outbound Frame Aggregation with Zero-Heap CorkBuffer") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[..256] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        let p_hdr = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        wing::encode_frame_header_to(p_hdr, wire);
        let ping_data: u8[8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        for b in ping_data { wire.push(b); }

        var cork = core::new_cork_buffer();
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, cork);

        sub.assert_true(ok, "Ingress succeeded with CorkBuffer");
        sub.assert_eq(consumed, wire.len, "Consumed entire client payload");
        sub.assert_gt(cork.cork_pending(), 0, "CorkBuffer contains emitted frames");

        let emitted = cork.cork_as_slice();
        // Frame 1: Server SETTINGS (33 bytes)
        // Frame 2: Server PING ACK (17 bytes)
        sub.assert_eq(cork.cork_pending(), 33 + 17, "Emitted SETTINGS (33) + PING ACK (17)");
        let f2_hdr, _ = wing::parse_frame_header(emitted[33 .. 42]);
        sub.assert_eq(f2_hdr.frame_type, wing::FRAME_PING, "Frame 2 is PING ACK in cork");
        sub.assert_true((f2_hdr.flags & wing::FLAG_ACK) != 0, "FLAG_ACK set on PING response");

        core::cork_consume(cork, 33);
        sub.assert_eq(cork.cork_pending(), 17, "Remaining 17 bytes after partial cork consume");
    };
}

// ============================================================================
// 2. Stream Multiplexing, Request Dispatching & HPACK Response Generation
// ============================================================================
fn test_h2_request_dispatch(t: core::T&) {
    t.run("H2-03: Single GET Request through Server Pipeline") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/api/greet", 101);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/api/greet", "127.0.0.1:8080", true, wire);

        var out_wire: u8[..1024] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "handle_h2_server_ingress succeeds on GET request");
        sub.assert_eq(consumed, wire.len, "Consumed entire client stream");

        // The response must contain:
        // 1. Server SETTINGS frame (33 bytes)
        // 2. Response HEADERS frame for stream 1
        sub.assert_gt(out_wire.len, 33, "Response has frames beyond initial SETTINGS");

        let resp_hdr, err_rh = wing::parse_frame_header(out_wire[33 .. 42]);
        sub.assert_eq(err_rh, wing::ERR_NO_ERROR, "Decoded response frame header");
        sub.assert_eq(resp_hdr.frame_type, wing::FRAME_HEADERS, "Response frame is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
        sub.assert_true((resp_hdr.flags & wing::FLAG_END_HEADERS) != 0, "Response has END_HEADERS");

        // Decode response headers with client HPACK table
        var dec_resp = wing::DecodedH2HeaderList { .. };
        let hpack_payload = out_wire[42 .. 42 + resp_hdr.length];
        let dec_err = wing::decode_hpack_header_block(client_hpack, hpack_payload, dec_resp);
        sub.assert_eq(dec_err, wing::ERR_NO_ERROR, "Client decoded response HPACK without error");

        // Verify :status == 200
        var found_status = false;
        var status_code_val: u8[..16] = [];
        for &f in dec_resp.fields {
            if f.name[..] == ":status" {
                found_status = true;
                status_code_val.clear();
                status_code_val.append(f.value[..]);
            }
        }
        sub.assert_true(found_status, "Found :status in response headers");
        sub.assert_bytes_eq(status_code_val[..], "200", ":status is 200");
    };

    t.run("H2-04: POST Request with DATA Frame Payload") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/api/data", 202);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        // Headers without END_STREAM
        encode_client_headers(client_hpack, 1, "POST", "/api/data", "127.0.0.1:8080", false, wire);
        // Data with END_STREAM
        encode_client_data(1, "payload_bytes_12345", true, wire);

        var out_wire: u8[..1024] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "handle_h2_server_ingress succeeds on POST with DATA");
        sub.assert_eq(consumed, wire.len, "Consumed entire client stream");
        sub.assert_gt(out_wire.len, 33, "Generated response");
    };

    t.run("H2-05: Concurrent Multiplexed Streams (Streams 1 and 3)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/first", 1);
        wing::add_route(pipeline.router, "GET", "/second", 2);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..1024] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        // Interleaved streams 1 and 3
        encode_client_headers(client_hpack, 1, "GET", "/first", "localhost", true, wire);
        encode_client_headers(client_hpack, 3, "GET", "/second", "localhost", true, wire);

        var out_wire: u8[..2048] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Both streams handled concurrently");
        sub.assert_eq(consumed, wire.len, "Consumed all incoming bytes");

        // Verify responses were emitted for both stream 1 and stream 3
        var found_stream_1 = false;
        var found_stream_3 = false;
        var off: i64 = 33; // skip Server SETTINGS (33B)

        while off + 9 <= out_wire.len {
            let f_hdr, err_f = wing::parse_frame_header(out_wire[off .. off + 9]);
            if err_f == wing::ERR_NO_ERROR && f_hdr.frame_type == wing::FRAME_HEADERS {
                if f_hdr.stream_id == 1 { found_stream_1 = true; }
                if f_hdr.stream_id == 3 { found_stream_3 = true; }
            }
            off += 9 + (f_hdr.length as i64);
        }

        sub.assert_true(found_stream_1, "Found response HEADERS on stream 1");
        sub.assert_true(found_stream_3, "Found response HEADERS on stream 3");
    };
}

// ============================================================================
// 3. End-to-End HttpServer Integration with HTTP/2 Preface Detection
// ============================================================================
fn test_h2_server_wire_integration(t: core::T&) {
    t.run("HttpServer.handle_connection_wire auto-detects H2 and serves requests") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/ping", 999);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire_in: u8[..512] = [];
        wire_in.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/ping", "127.0.0.1", true, wire_in);

        var wire_out: u8[..1024] = [];
        let outcome, ok = wing::handle_connection_wire(server, "127.0.0.1", wire_in[..], 1700000000000000, wire_out);

        sub.assert_true(ok, "handle_connection_wire succeeded on HTTP/2 stream");
        sub.assert_true(outcome == wing::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_gt(wire_out.len, 33, "Generated HTTP/2 response frames");
        sub.assert_ge(server.requests_processed, 1, "Requests processed incremented");
    };
}

// ============================================================================
// 4. CONTINUATION Assembly, Anti-DoS & Rapid Reset Defense
// ============================================================================
fn test_h2_continuation_and_anti_dos(t: core::T&) {
    t.run("H2-06: Multi-Frame CONTINUATION Header Assembly") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/split/headers", 200);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);

        // Prepend preface
        var wire: u8[..1024] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Encode full header block
        var hdr_block: u8[..512] = [];
        wing::encode_hpack_field(client_hpack, hdr_block, ":method", "GET", true, false);
        wing::encode_hpack_field(client_hpack, hdr_block, ":path", "/split/headers", true, false);
        wing::encode_hpack_field(client_hpack, hdr_block, ":scheme", "https", true, false);
        wing::encode_hpack_field(client_hpack, hdr_block, ":authority", "localhost", true, false);

        sub.assert_gt(hdr_block.len, 10, "Header block non-empty");

        // Split header block into two frames:
        // Frame 1: HEADERS (first 10 bytes, flags: END_STREAM, NO END_HEADERS)
        let part1 = hdr_block[..10];
        let part2 = hdr_block[10..];

        let h_hdr = wing::FrameHeader {
            length: part1.len as u32,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_STREAM, // No FLAG_END_HEADERS!
            stream_id: 1,
        };
        wing::encode_frame_header_to(h_hdr, wire);
        wire.append(part1);

        // Frame 2: CONTINUATION (remaining bytes, flags: END_HEADERS)
        let c_hdr = wing::FrameHeader {
            length: part2.len as u32,
            frame_type: wing::FRAME_CONTINUATION,
            flags: wing::FLAG_END_HEADERS, // Terminal CONTINUATION frame
            stream_id: 1,
        };
        wing::encode_frame_header_to(c_hdr, wire);
        wire.append(part2);

        var out_wire: u8[..1024] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on multi-frame CONTINUATION");
        sub.assert_eq(consumed, wire.len, "Consumed entire multi-frame payload");

        // Verify response was emitted for stream 1
        sub.assert_gt(out_wire.len, 33, "Emitted response frame");
        let resp_hdr, _ = wing::parse_frame_header(out_wire[33 .. 42]);
        sub.assert_eq(resp_hdr.frame_type, wing::FRAME_HEADERS, "Response is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
    };

    t.run("H2-07: Ban Zero-Length Non-Terminal CONTINUATION (CVE-2024-2758 / CVE-2024-31309)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[..512] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS without END_HEADERS
        let h_hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_HEADERS,
            flags: 0,
            stream_id: 1,
        };
        wing::encode_frame_header_to(h_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        // Frame 2: Zero-length non-terminal CONTINUATION frame (CVE-2024-2758 exploit attempt)
        let c_hdr = wing::FrameHeader {
            length: 0,
            frame_type: wing::FRAME_CONTINUATION,
            flags: 0, // No END_HEADERS!
            stream_id: 1,
        };
        wing::encode_frame_header_to(c_hdr, wire);

        var out_wire: u8[..512] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        // Must reject with GOAWAY PROTOCOL_ERROR
        sub.assert_false(ok, "Ingress rejected zero-length non-terminal CONTINUATION");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = wing::parse_frame_header(out_wire[33 .. 42]);
        sub.assert_eq(g_hdr.frame_type, wing::FRAME_GOAWAY, "Frame is GOAWAY");
    };

    t.run("H2-08: Rapid Reset Batch Bypass (CVE-2023-44487)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/fast/reset", 50);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);

        var wire: u8[..512] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS stream 1
        encode_client_headers(client_hpack, 1, "GET", "/fast/reset", "localhost", true, wire);

        // Frame 2: Immediate RST_STREAM stream 1 (Rapid Reset attack pattern)
        let rst_hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_RST_STREAM,
            flags: 0,
            stream_id: 1,
        };
        wing::encode_frame_header_to(rst_hdr, wire);
        let err_code: u8[4] = [0x00, 0x00, 0x00, 0x08]; // CANCEL (0x8)
        for b in err_code { wire.push(b); }

        var out_wire: u8[..512] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress safely handled rapid reset batch");
        sub.assert_eq(consumed, wire.len, "Consumed entire batch");

        // Server SETTINGS was emitted (33 bytes), but NO stream response was dispatched for stream 1!
        sub.assert_eq(out_wire.len, 33, "No response pipeline dispatch occurred for cancelled stream");
    };
}

fn main() {
    var runner = core::new_runner("HTTP/2 Server Frame Multiplexer Conformance Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Preface, Handshake & Settings Negotiation", test_h2_handshake_and_settings);
    core::run_case(runner, "2. Stream Multiplexing & Pipeline Dispatch", test_h2_request_dispatch);
    core::run_case(runner, "3. HttpServer End-to-End HTTP/2 Integration", test_h2_server_wire_integration);
    core::run_case(runner, "4. CONTINUATION Assembly, Anti-DoS & Rapid Reset", test_h2_continuation_and_anti_dos);
    let ok = core::finish(runner);
    assert(ok);
}
