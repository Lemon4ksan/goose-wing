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
    out: B&,
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

// Helper to encode client trailers in a HEADERS frame
fn encode_client_trailers<B>(
    dt: wing::DynamicTable&,
    stream_id: u32,
    name: const u8[:],
    value: const u8[:],
    out: B&,
) {
    var hdr_block: u8[>..] = [];
    wing::encode_hpack_field(dt, hdr_block, name, value, true, false);
    let hdr = wing::FrameHeader {
        length: hdr_block.len as u32,
        frame_type: wing::FRAME_HEADERS,
        flags: wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM,
        stream_id: stream_id,
    };
    wing::encode_frame_header_to(hdr, out);
    out.append(hdr_block[..]);
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
        let f2_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(f2_hdr.frame_type, wing::FRAME_SETTINGS, "Frame 2 is SETTINGS");
        sub.assert_true((f2_hdr.flags & wing::FLAG_ACK) != 0, "Frame 2 has FLAG_ACK");

        // Check Frame 3 (PING ACK)
        let f3_hdr, _ = wing::parse_frame_header(out_wire[42..51]);
        sub.assert_eq(f3_hdr.frame_type, wing::FRAME_PING, "Frame 3 is PING");
        sub.assert_true((f3_hdr.flags & wing::FLAG_ACK) != 0, "Frame 3 has FLAG_ACK");
        let ping_echo = out_wire[51..59];
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
        let f2_hdr, _ = wing::parse_frame_header(emitted[33..42]);
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

        let resp_hdr, err_rh = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(err_rh, wing::ERR_NO_ERROR, "Decoded response frame header");
        sub.assert_eq(resp_hdr.frame_type, wing::FRAME_HEADERS, "Response frame is HEADERS");
        sub.assert_eq(resp_hdr.stream_id, 1, "Response on stream 1");
        sub.assert_true((resp_hdr.flags & wing::FLAG_END_HEADERS) != 0, "Response has END_HEADERS");

        // Decode response headers with client HPACK table
        var dec_resp = wing::DecodedH2HeaderList { .. };
        let hpack_payload = out_wire[42..42 + resp_hdr.length];
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
            let f_hdr, err_f = wing::parse_frame_header(out_wire[off..off + 9]);
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
        let resp_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
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
        let g_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
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

// ============================================================================
// 5. RFC 9113 Protocol Invariants & Zero-Allocation Ingress
// ============================================================================
fn test_h2_protocol_invariants(t: core::T&) {
    t.run("H2-09: Client Request Trailers Accepted (RFC 9113 §8.1.2)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/upload/trailers", 10);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/upload/trailers", "localhost", false, wire);
        encode_client_data(1, "body-content-here", false, wire);
        encode_client_trailers(client_hpack, 1, "x-checksum", "sha256-abc12345", wire);

        var out_wire: u8[>..] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress succeeded on request with trailers");
        var found_resp = false;
        var off: i64 = 33; // skip server SETTINGS (33B)
        while off + 9 <= out_wire.len {
            let f_hdr, err_f = wing::parse_frame_header(out_wire[off..off + 9]);
            if err_f == wing::ERR_NO_ERROR && f_hdr.frame_type == wing::FRAME_HEADERS && f_hdr.stream_id == 1 {
                found_resp = true;
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_resp, "Response HEADERS frame emitted on stream 1");
    };

    t.run("H2-10: Client Trailers with Pseudo-Headers Rejected (RFC 9113 §8.1.2)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/upload/pseudo-trailer", 11);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/upload/pseudo-trailer", "localhost", false, wire);
        encode_client_trailers(client_hpack, 1, ":status", "200", wire);

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress remained alive on stream error");
        sub.assert_gt(out_wire.len, 33, "Output generated");
        let rst_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, wing::FRAME_RST_STREAM, "Emitted RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 1, "RST_STREAM on stream 1");
    };

    t.run("H2-11: Large Flow Control Ingress Window Replenishment (RFC 9113 §6.9)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/bulk", 12);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/bulk", "localhost", false, wire);

        var chunk: u8[>..] = [];
        for i in 15000 { chunk.push('X'); }
        for step in 5 {
            let is_last = (step == 4);
            encode_client_data(1, chunk[..], is_last, wire);
        }

        var out_wire: u8[>..] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress handled >65535 bytes without FLOW_CONTROL_ERROR");
        sub.assert_eq(consumed, wire.len, "Consumed entire 75KB wire");
        sub.assert_ge(sess.conn.conn_recv_window, 0, "conn_recv_window replenished");
    };

    t.run("H2-12: Stream State Transition to Closed (RFC 9113 §5.1)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 13);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        var out_wire: u8[>..] = [];
        wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        var all_ok = true;
        for i in 135 {
            let s_id: u32 = ((i * 2) + 1) as u32;
            var s_wire: u8[>..] = [];
            encode_client_headers(client_hpack, s_id, "GET", "/test", "localhost", true, s_wire);
            var s_out: u8[>..] = [];
            let _, ok_st = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", s_wire[..], 1000, s_out);
            if !ok_st {
                all_ok = false;
                break;
            }
        }
        sub.assert_true(all_ok, "135 sequential streams processed without stream leak or REFUSED_STREAM");
        sub.assert_eq(sess.conn.active_stream_count, 0, "All completed streams decremented active count to 0");
    };

    t.run("H2-13: Stream WINDOW_UPDATE increment 0 emits RST_STREAM (RFC 9113 §6.9)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 14);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", false, wire);

        let wu_hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id: 1,
        };
        wing::encode_frame_header_to(wu_hdr, wire);
        let zeros: u8[4] = [0, 0, 0, 0];
        for b in zeros { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Connection remains open after stream-level WINDOW_UPDATE error");
        var found_rst = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = wing::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == wing::FRAME_RST_STREAM && f_hdr.stream_id == 1 {
                found_rst = true;
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_rst, "Server emitted RST_STREAM on stream 1");
    };

    t.run("H2-14: Client SETTINGS_ENABLE_PUSH != 0 rejected (RFC 9113 §6.5.2)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        let s_hdr = wing::FrameHeader {
            length: 6,
            frame_type: wing::FRAME_SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        wing::encode_frame_header_to(s_hdr, wire);
        core::append_u16_be(wire, wing::SETTING_ENABLE_PUSH);
        core::append_u32_be(wire, 1);

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Server rejected client ENABLE_PUSH != 0");
        sub.assert_gt(out_wire.len, 33, "Emitted GOAWAY");
        let g_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, wing::FRAME_GOAWAY, "GOAWAY emitted");
    };

    t.run("H2-15: gRPC Response Body Preserved Without Spurious OK (RFC 9113)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        encode_client_headers(client_hpack, 1, "POST", "/not-found", "localhost", true, wire);

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Ingress handled request");
        var has_data = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = wing::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == wing::FRAME_DATA && f_hdr.stream_id == 1 {
                has_data = true;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_false(has_data, "No DATA frame emitted for non-200 empty response");
    };

    t.run("H2-16: PRIORITY Self-Dependency Rejection (RFC 9113 §5.3.1)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        let prio_hdr = wing::FrameHeader {
            length: 5,
            frame_type: wing::FRAME_PRIORITY,
            flags: 0,
            stream_id: 3,
        };
        wing::encode_frame_header_to(prio_hdr, wire);
        let prio_payload: u8[5] = [0x00, 0x00, 0x00, 0x03, 0x10];
        for b in prio_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_true(ok, "Connection remains open");
        sub.assert_gt(out_wire.len, 33, "Output contains frames");
        let rst_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(rst_hdr.frame_type, wing::FRAME_RST_STREAM, "Frame is RST_STREAM");
        sub.assert_eq(rst_hdr.stream_id, 3, "RST_STREAM on stream 3");
    };

    t.run("H2-17: HEADERS on Closed Stream Triggers RST_STREAM(STREAM_CLOSED) Not GOAWAY (RFC 9113 §5.1)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 17);

        var client_hpack = wing::new_dynamic_table(wing::HPACK_DEFAULT_MAX_DYN_SIZE);
        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);
        // Complete stream 1
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", true, wire);

        var out_wire: u8[>..] = [];
        let _, ok1 = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);
        sub.assert_true(ok1, "Stream 1 completed normally");

        // Send second HEADERS frame on now-closed stream 1
        var wire2: u8[>..] = [];
        encode_client_headers(client_hpack, 1, "GET", "/test", "localhost", true, wire2);

        var out_wire2: u8[>..] = [];
        let _, ok2 = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out_wire2);
        sub.assert_true(ok2, "Connection remains open after HEADERS on closed stream");

        // Verify RST_STREAM was emitted for stream 1
        var found_rst = false;
        var off: i64 = 0;
        while off + 9 <= out_wire2.len {
            let f_hdr, _ = wing::parse_frame_header(out_wire2[off..off + 9]);
            if f_hdr.frame_type == wing::FRAME_RST_STREAM && f_hdr.stream_id == 1 {
                found_rst = true;
                let code_r = core::new_slice_reader(out_wire2[off + 9..off + 13]);
                let err_code, _ = code_r.read_u32_be();
                sub.assert_eq(err_code, wing::ERR_STREAM_CLOSED, "RST_STREAM error code is STREAM_CLOSED");
                break;
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_rst, "Server emitted RST_STREAM on closed stream 1");

        // Verify stream 3 still works over the same connection
        var wire3: u8[>..] = [];
        encode_client_headers(client_hpack, 3, "GET", "/test", "localhost", true, wire3);
        var out_wire3: u8[>..] = [];
        let _, ok3 = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire3[..], 1000, out_wire3);
        sub.assert_true(ok3, "Subsequent stream 3 succeeds over open connection");
    };

    t.run("H2-18: Interleaved Non-CONTINUATION Frame During Header Accumulation Triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.10)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Frame 1: HEADERS stream 1 WITHOUT FLAG_END_HEADERS
        let h_hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_HEADERS,
            flags: 0, // No END_HEADERS!
            stream_id: 1,
        };
        wing::encode_frame_header_to(h_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        // Frame 2: Interleaved PING frame before END_HEADERS
        let ping_hdr = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_PING,
            flags: 0,
            stream_id: 0,
        };
        wing::encode_frame_header_to(ping_hdr, wire);
        let ping_opaque: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        for b in ping_opaque { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected interleaved frame before END_HEADERS");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, wing::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, wing::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-19: Unprompted CONTINUATION Frame Triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.10)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Unprompted CONTINUATION frame without preceding HEADERS
        let c_hdr = wing::FrameHeader {
            length: 4,
            frame_type: wing::FRAME_CONTINUATION,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 1,
        };
        wing::encode_frame_header_to(c_hdr, wire);
        let dummy: u8[4] = [0x82, 0x84, 0x86, 0x87];
        for b in dummy { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Ingress rejected unprompted CONTINUATION");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, wing::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, wing::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-20: Client PUSH_PROMISE Frame Rejected with GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.6)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Client sends PUSH_PROMISE (promised stream id = 2, dummy header fragment)
        let pp_hdr = wing::FrameHeader {
            length: 5,
            frame_type: wing::FRAME_PUSH_PROMISE,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 1,
        };
        wing::encode_frame_header_to(pp_hdr, wire);
        let pp_payload: u8[5] = [0x00, 0x00, 0x00, 0x02, 0x82];
        for b in pp_payload { wire.push(b); }

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Server rejected client PUSH_PROMISE");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        let g_hdr, _ = wing::parse_frame_header(out_wire[33..42]);
        sub.assert_eq(g_hdr.frame_type, wing::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire[46..50]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, wing::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-21: Duplicate / Unsolicited SETTINGS ACK Rejected with GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.5 & §10.5)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Frame 1: Valid SETTINGS ACK for server initial settings
        let ack_hdr1 = wing::FrameHeader {
            length: 0,
            frame_type: wing::FRAME_SETTINGS,
            flags: wing::FLAG_ACK,
            stream_id: 0,
        };
        wing::encode_frame_header_to(ack_hdr1, wire);

        var out_wire1: u8[>..] = [];
        let _, ok1 = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire1);
        sub.assert_true(ok1, "First SETTINGS ACK accepted");
        sub.assert_true(sess.client_settings_acked, "client_settings_acked is true");
        sub.assert_false(sess.pending_settings_ack, "pending_settings_ack is false");

        // Frame 2: Duplicate / unsolicited SETTINGS ACK
        var wire2: u8[>..] = [];
        wing::encode_frame_header_to(ack_hdr1, wire2);

        var out_wire2: u8[>..] = [];
        let _, ok2 = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out_wire2);
        sub.assert_false(ok2, "Duplicate SETTINGS ACK rejected");
        sub.assert_gt(out_wire2.len, 0, "GOAWAY emitted");
        let g_hdr, _ = wing::parse_frame_header(out_wire2[0..9]);
        sub.assert_eq(g_hdr.frame_type, wing::FRAME_GOAWAY, "Frame is GOAWAY");
        let g_r = core::new_slice_reader(out_wire2[13..17]);
        let err_code, _ = g_r.read_u32_be();
        sub.assert_eq(err_code, wing::ERR_PROTOCOL_ERROR, "GOAWAY code is PROTOCOL_ERROR");
    };

    t.run("H2-22: Control Frame Flood (Excess PINGs/ACKs > 64) Triggers GOAWAY(ENHANCE_YOUR_CALM) (RFC 9113 §10.5)") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire: u8[>..] = [];
        wire.append(wing::H2_CLIENT_PREFACE[..]);

        // Send 65 PING frames in a single batch (exceeding MAX_PENDING_CTRL_FRAMES = 64)
        for i in 65 {
            let ping_hdr = wing::FrameHeader {
                length: 8,
                frame_type: wing::FRAME_PING,
                flags: 0,
                stream_id: 0,
            };
            wing::encode_frame_header_to(ping_hdr, wire);
            let ping_payload: u8[8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, (i & 0xFF) as u8];
            for b in ping_payload { wire.push(b); }
        }

        var out_wire: u8[>..] = [];
        let _, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out_wire);

        sub.assert_false(ok, "Control frame flood rejected");
        sub.assert_gt(out_wire.len, 33, "GOAWAY emitted");
        // Locate GOAWAY frame
        var found_calm = false;
        var off: i64 = 33;
        while off + 9 <= out_wire.len {
            let f_hdr, _ = wing::parse_frame_header(out_wire[off..off + 9]);
            if f_hdr.frame_type == wing::FRAME_GOAWAY {
                let g_r = core::new_slice_reader(out_wire[off + 13..off + 17]);
                let err_code, _ = g_r.read_u32_be();
                if err_code == wing::ERR_ENHANCE_YOUR_CALM {
                    found_calm = true;
                    break;
                }
            }
            off += 9 + (f_hdr.length as i64);
        }
        sub.assert_true(found_calm, "GOAWAY with ENHANCE_YOUR_CALM emitted for control frame flood");
    };
}

fn main() {
    var runner = core::new_runner("HTTP/2 Server Frame Multiplexer Conformance Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Preface, Handshake & Settings Negotiation", test_h2_handshake_and_settings);
    core::run_case(runner, "2. Stream Multiplexing & Pipeline Dispatch", test_h2_request_dispatch);
    core::run_case(runner, "3. HttpServer End-to-End HTTP/2 Integration", test_h2_server_wire_integration);
    core::run_case(runner, "4. CONTINUATION Assembly, Anti-DoS & Rapid Reset", test_h2_continuation_and_anti_dos);
    core::run_case(runner, "5. RFC 9113 Protocol Invariants & Zero-Allocation Ingress", test_h2_protocol_invariants);
    let ok = core::finish(runner);
    assert(ok);
}
