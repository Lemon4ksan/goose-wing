// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/grpc_test.goose
// Verification Suite for gRPC over HTTP/2, HTTP/3, and gRPC-Web Protocol Engine.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. gRPC LPM Binary Framing & Codec
// ----------------------------------------------------------------------------
fn test_grpc_lpm_framing(t: lit::T&) {
    t.run("1. Uncompressed 5-Byte LPM Frame Encoding & Decoding") { sub =>
        let msg = "Hello gRPC Zero-Heap World!";
        var wire: u8[>..] = [];
        grpc::encode_lpm(msg, wire, false);

        sub.assert_eq(wire.len, (5 + msg.len) as i64, "Total wire length is 5-byte header + payload");
        sub.assert_eq(wire[0], 0x00, "Flag byte is 0x00 for uncompressed");

        let expected_len = msg.len as u32;
        let wire_len = ((wire[1] as u32) << 24) |
                       ((wire[2] as u32) << 16) |
                       ((wire[3] as u32) << 8) |
                       (wire[4] as u32);
        sub.assert_eq(wire_len, expected_len, "Wire big-endian length matches message length");

        // Decode
        var decoded_payload: u8[>..] = [];
        var is_comp = true;
        let consumed, ok_dec = grpc::decode_lpm(wire[..], 0, decoded_payload, is_comp);

        sub.assert_true(ok_dec, "LPM decoded successfully");
        sub.assert_eq(consumed, wire.len as u32, "Consumed full wire slice");
        sub.assert_false(is_comp, "Compression flag correctly reported as false");
        sub.assert_bytes_eq(decoded_payload[..], msg, "Decoded payload matches original message");
    };

    t.run("2. Compressed LPM Framing") { sub =>
        let msg = "Compressed Protobuf Binary Bytes";
        var wire: u8[>..] = [];
        grpc::encode_lpm(msg, wire, true);

        sub.assert_eq(wire[0], rfc::GRPC_FLAG_COMPRESSED, "Flag byte is 0x01 (GRPC_FLAG_COMPRESSED)");

        var decoded: u8[>..] = [];
        var is_comp = false;
        let consumed, ok_dec = grpc::decode_lpm(wire[..], 0, decoded, is_comp);

        sub.assert_true(ok_dec, "LPM decoded");
        sub.assert_eq(consumed, wire.len as u32, "Consumed full compressed frame");
        sub.assert_true(is_comp, "Compression flag reported as true");

        var decomp: u8[>..] = [];
        let ok_gz, _ = core::gzip_decompress_with_limit(decoded[..], decomp, 4096);
        sub.assert_true(ok_gz, "Gzip decompression succeeded");
        sub.assert_bytes_eq(decomp[..], msg, "Payload restored");
    };

    t.run("3. Zero-Length Empty LPM Frame") { sub =>
        var wire: u8[>..] = [];
        grpc::encode_lpm("", wire, false);

        sub.assert_eq(wire.len, 5, "Empty message is exactly 5 bytes");
        sub.assert_eq(wire[0], 0, "Flag is 0");
        sub.assert_eq(wire[1], 0, "Len byte 1 is 0");
        sub.assert_eq(wire[2], 0, "Len byte 2 is 0");
        sub.assert_eq(wire[3], 0, "Len byte 3 is 0");
        sub.assert_eq(wire[4], 0, "Len byte 4 is 0");

        var decoded: u8[>..] = [];
        var is_comp = false;
        let consumed, ok_dec = grpc::decode_lpm(wire[..], 0, decoded, is_comp);

        sub.assert_true(ok_dec, "Decoded empty message");
        sub.assert_eq(consumed, 5, "Consumed 5 bytes");
        sub.assert_eq(decoded.len, 0, "Decoded payload is empty");
    };

    t.run("4. Truncated Frame Guards") { sub =>
        let msg = "Test Truncation";
        var wire: u8[>..] = [];
        grpc::encode_lpm(msg, wire, false);

        var decoded: u8[>..] = [];
        var is_comp = false;

        // Truncate header (< 5 bytes)
        let _, ok_hdr = grpc::decode_lpm(wire[..4], 0, decoded, is_comp);
        sub.assert_false(ok_hdr, "Truncated header rejected");

        // Truncate payload
        let _, ok_pay = grpc::decode_lpm(wire[..(wire.len - 2)], 0, decoded, is_comp);
        sub.assert_false(ok_pay, "Truncated payload rejected");

        // Reserved flag bits rejected per gRPC Wire Protocol
        var bad_flag_wire: u8[5] = [0x02, 0, 0, 0, 0];
        let _, ok_bad_flag = grpc::decode_lpm(bad_flag_wire[..], 0, decoded, is_comp);
        sub.assert_false(ok_bad_flag, "Reserved flag bit 0x02 rejected");
    };

    t.run("5. Concatenated Multi-LPM Sequential Extraction") { sub =>
        var stream_bytes: u8[>..] = [];
        grpc::encode_lpm("Message1", stream_bytes, false);
        grpc::encode_lpm("Message2", stream_bytes, true);
        grpc::encode_lpm("Message3", stream_bytes, false);

        var offset: u32 = 0;
        var count = 0;
        var payloads:   u8[..64][..4] = [];
        var comp_flags: bool[..4]     = [];

        while offset < (stream_bytes.len as u32) {
            var msg_buf: u8[..64] = [];
            var comp = false;
            let consumed, ok_msg = grpc::decode_lpm(stream_bytes[..], offset, msg_buf, comp);
            guard ok_msg else { break; }
            payloads.push(msg_buf);
            comp_flags.push(comp);
            offset += consumed;
            count++;
        }

        sub.assert_eq(count, 3, "Parsed 3 consecutive LPM frames");
        sub.assert_bytes_eq(payloads[0][..], "Message1", "1st payload");
        sub.assert_false(comp_flags[0], "1st uncompressed");
        sub.assert_true(comp_flags[1], "2nd compressed");
        var decomp2: u8[..64] = [];
        let ok_gz2, _ = core::gzip_decompress_with_limit(payloads[1][..], decomp2, 64);
        sub.assert_true(ok_gz2, "2nd payload gzip decompressed");
        sub.assert_bytes_eq(decomp2[..], "Message2", "2nd payload");
        sub.assert_bytes_eq(payloads[2][..], "Message3", "3rd payload");
        sub.assert_false(comp_flags[2], "3rd uncompressed");
    };
}

// ----------------------------------------------------------------------------
// 2. gRPC Incremental Streaming Stream Parser
// ----------------------------------------------------------------------------
fn test_grpc_streaming_parser(t: lit::T&) {
    t.run("1. Piecewise Fragmented Ingestion Across DATA Frame Chunks") { sub =>
        var parser = grpc::new_stream_parser();

        let full_msg = "Chunked Streaming gRPC Verification Payload!";
        var wire: u8[>..] = [];
        grpc::encode_lpm(full_msg, wire, false);

        // Feed chunk 1: 3 bytes of header
        sub.assert_true(parser.feed(wire[..3]), "Feed chunk 1 via UFCS");
        var out_msg: u8[>..] = [];
        var is_comp = false;
        sub.assert_false(parser.next_message(out_msg, is_comp), "Incomplete header yields no message");

        // Feed chunk 2: remaining 2 bytes of header + 10 bytes of payload
        sub.assert_true(parser.feed(wire[3..15]), "Feed chunk 2 via UFCS");
        sub.assert_false(parser.next_message(out_msg, is_comp), "Partial payload yields no message");

        // Feed chunk 3: remainder of payload
        sub.assert_true(parser.feed(wire[15..]), "Feed chunk 3 via UFCS");
        sub.assert_true(parser.next_message(out_msg, is_comp), "Complete message assembled and extracted");
        sub.assert_bytes_eq(out_msg[..], full_msg, "Assembled message matches");
        sub.assert_false(is_comp, "Is uncompressed");

        // Stream parser should now be empty
        sub.assert_false(parser.next_message(out_msg, is_comp), "Buffer empty after extraction");

        parser.reset();
        sub.assert_eq(parser.buf.len, 0, "Parser reset clears buffer");
    };

    t.run("2. Multiple Stream Messages in Single Chunk") { sub =>
        var parser = grpc::new_stream_parser();

        var multi: u8[>..] = [];
        grpc::encode_lpm("Alpha", multi, false);
        grpc::encode_lpm("Beta", multi, false);
        grpc::encode_lpm("Gamma", multi, false);

        sub.assert_true(parser.feed(multi[..]), "Feed all 3 messages together via UFCS");

        var m1: u8[..32] = [];
        var c1 = false;
        sub.assert_true(parser.next_message(m1, c1), "First message popped");
        sub.assert_bytes_eq(m1[..], "Alpha", "Message 1 is Alpha");

        var m2: u8[..32] = [];
        var c2 = false;
        sub.assert_true(parser.next_message(m2, c2), "Second message popped");
        sub.assert_bytes_eq(m2[..], "Beta", "Message 2 is Beta");

        var m3: u8[..32] = [];
        var c3 = false;
        sub.assert_true(parser.next_message(m3, c3), "Third message popped");
        sub.assert_bytes_eq(m3[..], "Gamma", "Message 3 is Gamma");

        var m4: u8[..32] = [];
        var c4 = false;
        sub.assert_false(parser.next_message(m4, c4), "No more messages left");
    };
}

// ----------------------------------------------------------------------------
// 3. gRPC Status Codes, Timeout & Percent-Encoded Messages
// ----------------------------------------------------------------------------
fn test_grpc_status_and_metadata(t: lit::T&) {
    t.run("1. Canonical Status Code Mapping (0..16)") { sub =>
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.Ok), 0, "OK code 0");
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.Cancelled), 1, "Cancelled code 1");
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.InvalidArgument), 3, "InvalidArgument code 3");
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.DeadlineExceeded), 4, "DeadlineExceeded code 4");
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.NotFound), 5, "NotFound code 5");
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.PermissionDenied), 7, "PermissionDenied code 7");
        sub.assert_eq(grpc::status_to_code(grpc::StatusCode.Unauthenticated), 16, "Unauthenticated code 16");

        sub.assert_bytes_eq(grpc::status_name(grpc::StatusCode.Ok), "OK", "Name OK");
        sub.assert_bytes_eq(grpc::status_name(grpc::StatusCode.Internal), "INTERNAL", "Name INTERNAL");
        sub.assert_bytes_eq(grpc::status_name(grpc::StatusCode.Unavailable), "UNAVAILABLE", "Name UNAVAILABLE");

        // HTTP status fallbacks per gRPC HTTP/2 Status Mapping
        sub.assert_eq(grpc::status_from_http(200), grpc::StatusCode.Unknown, "HTTP 200 without grpc-status -> Unknown");
        sub.assert_eq(grpc::status_from_http(400), grpc::StatusCode.Internal, "HTTP 400 -> Internal");
        sub.assert_eq(grpc::status_from_http(401), grpc::StatusCode.Unauthenticated, "HTTP 401 -> Unauthenticated");
        sub.assert_eq(grpc::status_from_http(403), grpc::StatusCode.PermissionDenied, "HTTP 403 -> PermissionDenied");
        sub.assert_eq(grpc::status_from_http(404), grpc::StatusCode.Unimplemented, "HTTP 404 -> Unimplemented");
        sub.assert_eq(grpc::status_from_http(429), grpc::StatusCode.ResourceExhausted, "HTTP 429 -> ResourceExhausted");
        sub.assert_eq(grpc::status_from_http(503), grpc::StatusCode.Unavailable, "HTTP 503 -> Unavailable");
        sub.assert_eq(grpc::status_from_http(504), grpc::StatusCode.DeadlineExceeded, "HTTP 504 -> DeadlineExceeded");
    };

    t.run("2. grpc-message Percent-Encoding & Decoding") { sub =>
        let raw = "Record with ID #42 not found: user%account";
        var encoded: u8[>..] = [];
        grpc::encode_message(raw, encoded);

        // '%' and '#' must be percent encoded
        var decoded: u8[>..] = [];
        grpc::decode_message(encoded[..], decoded);
        sub.assert_bytes_eq(decoded[..], raw, "Percent decode restores original error message exactly");

        // Verify non-ASCII characters
        let non_ascii: u8[3] = [0xE2, 0x82, 0xAC]; // Euro symbol in UTF-8
        var enc_na: u8[>..] = [];
        grpc::encode_message(non_ascii[..], enc_na);
        sub.assert_bytes_eq(enc_na[..], "%E2%82%AC", "Non-ASCII encoded as %XX uppercase hex");

        var dec_na: u8[>..] = [];
        grpc::decode_message(enc_na[..], dec_na);
        sub.assert_bytes_eq(dec_na[..], non_ascii[..], "Decoded non-ASCII matches");
    };

    t.run("3. grpc-timeout Formatting & Parsing") { sub =>
        var out_t: u8[..32] = [];

        // Exact seconds
        grpc::encode_timeout(10000, out_t);
        sub.assert_bytes_eq(out_t[..], "10S", "10000ms encoded as 10S");

        // Exact minutes
        out_t.clear();
        grpc::encode_timeout(120000, out_t);
        sub.assert_bytes_eq(out_t[..], "2M", "120000ms encoded as 2M");

        // Exact hours
        out_t.clear();
        grpc::encode_timeout(7200000, out_t);
        sub.assert_bytes_eq(out_t[..], "2H", "7200000ms encoded as 2H");

        // Milliseconds
        out_t.clear();
        grpc::encode_timeout(500, out_t);
        sub.assert_bytes_eq(out_t[..], "500m", "500ms encoded as 500m");

        // Parsing
        let ms_s, ok_s = grpc::parse_timeout("10S");
        sub.assert_true(ok_s, "Parsed 10S");
        sub.assert_eq(ms_s, 10000, "10S is 10000ms");

        let ms_m, ok_m = grpc::parse_timeout("500m");
        sub.assert_true(ok_m, "Parsed 500m");
        sub.assert_eq(ms_m, 500, "500m is 500ms");

        let ms_u, ok_u = grpc::parse_timeout("1000u");
        sub.assert_true(ok_u, "Parsed 1000u");
        sub.assert_eq(ms_u, 1, "1000 microseconds is 1ms");

        let ms_h, ok_h = grpc::parse_timeout("1H");
        sub.assert_true(ok_h, "Parsed 1H");
        sub.assert_eq(ms_h, 3600000, "1H is 3600000ms");
    };

    t.run("4. Status Extraction from Response Headers and Trailers") { sub =>
        var headers = http::HeaderMap { .. };
        headers.status_code = 200;

        var trailers = http::HeaderMap { .. };
        http::append_header(trailers, "grpc-status", "0");
        http::append_header(trailers, "grpc-message", "OK");

        var status = grpc::StatusCode.Unknown;
        var msg: u8[..256] = [];
        let has_status = grpc::extract_status(headers, trailers, status, msg);

        sub.assert_true(has_status, "Explicit status extracted from trailers");
        sub.assert_eq(status, grpc::StatusCode.Ok, "Status is OK");
        sub.assert_bytes_eq(msg[..], "OK", "Message is OK");

        // Trailers-only response (immediate error in headers)
        var err_headers = http::HeaderMap { .. };
        err_headers.status_code = 200;
        http::append_header(err_headers, "grpc-status", "7");
        http::append_header(err_headers, "grpc-message", "permission%20denied");

        var empty_trailers = http::HeaderMap { .. };
        let has_err = grpc::extract_status(err_headers, empty_trailers, status, msg);
        sub.assert_true(has_err, "Status extracted from headers in Trailers-Only case");
        sub.assert_eq(status, grpc::StatusCode.PermissionDenied, "Status is PermissionDenied");
        sub.assert_bytes_eq(msg[..], "permission denied", "Message unescaped");
    };
}

// ----------------------------------------------------------------------------
// 4. gRPC-Web Binary & Base64 Text Framing
// ----------------------------------------------------------------------------
fn test_grpc_web_framing(t: lit::T&) {
    t.run("1. Trailers-in-Body Encoding with Flag 0x80") { sub =>
        var web_trailers: u8[>..] = [];
        grpc::encode_web_trailers(grpc::StatusCode.InvalidArgument, "invalid argument provided", web_trailers);

        sub.assert_eq(web_trailers[0], rfc::GRPC_WEB_FLAG_TRAILERS, "Flag has bit 7 set (0x80)");

        var payload: u8[>..] = [];
        var is_trailers = false;
        var is_comp = false;
        let consumed, ok_dec = grpc::decode_web_frame(web_trailers[..], 0, payload, is_trailers, is_comp);

        sub.assert_true(ok_dec, "Frame decoded");
        sub.assert_true(is_trailers, "Frame marked as trailers");
        sub.assert_false(is_comp, "Uncompressed");

        var st = grpc::StatusCode.Ok;
        var msg: u8[..256] = [];
        let parsed = grpc::parse_web_trailers(payload[..], st, msg);
        sub.assert_true(parsed, "Parsed gRPC-Web trailers block");
        sub.assert_eq(st, grpc::StatusCode.InvalidArgument, "Status is InvalidArgument");
        sub.assert_bytes_eq(msg[..], "invalid argument provided", "Message extracted");
    };

    t.run("2. gRPC-Web Binary Response Stream with Data + Trailers") { sub =>
        var stream: u8[>..] = [];

        // Data frame
        let data_msg = "Unary Response Data Payload";
        grpc::encode_lpm(data_msg, stream, false);

        // Trailer frame (flag 0x80)
        grpc::encode_web_trailers(grpc::StatusCode.Ok, "OK", stream);

        var offset: u32 = 0;

        // Frame 1: Data
        var f1_payload: u8[>..] = [];
        var f1_is_trailers = false;
        var f1_comp = false;
        let cons1, ok_f1 = grpc::decode_web_frame(stream[..], offset, f1_payload, f1_is_trailers, f1_comp);
        sub.assert_true(ok_f1, "Decoded f1");
        sub.assert_false(f1_is_trailers, "f1 is data");
        sub.assert_bytes_eq(f1_payload[..], data_msg, "Data payload matches");
        offset += cons1;

        // Frame 2: Trailers
        var f2_payload: u8[>..] = [];
        var f2_is_trailers = false;
        var f2_comp = false;
        let cons2, ok_f2 = grpc::decode_web_frame(stream[..], offset, f2_payload, f2_is_trailers, f2_comp);
        sub.assert_true(ok_f2, "Decoded f2");
        sub.assert_true(f2_is_trailers, "f2 is trailers");

        var st = grpc::StatusCode.Unknown;
        var msg: u8[..256] = [];
        grpc::parse_web_trailers(f2_payload[..], st, msg);
        sub.assert_eq(st, grpc::StatusCode.Ok, "Status OK in trailers");
    };

    t.run("3. gRPC-Web Text Base64 Stream Codec") { sub =>
        var binary_stream: u8[>..] = [];
        grpc::encode_lpm("Base64 Encoded gRPC Message", binary_stream, false);

        var b64_text: u8[>..] = [];
        grpc::encode_web_text(binary_stream[..], b64_text);
        sub.assert_true(b64_text.len > binary_stream.len, "Base64 text produced");

        var restored_bin: u8[>..] = [];
        let ok_dec = grpc::decode_web_text(b64_text[..], restored_bin);
        sub.assert_true(ok_dec, "Decoded base64 text");
        sub.assert_bytes_eq(restored_bin[..], binary_stream[..], "Restored binary bytes match exactly");

        var msg: u8[>..] = [];
        var comp = false;
        let _, ok_lpm = grpc::decode_lpm(restored_bin[..], 0, msg, comp);
        sub.assert_true(ok_lpm, "LPM extracted from decoded Base64");
        sub.assert_bytes_eq(msg[..], "Base64 Encoded gRPC Message", "Payload correct");
    };
}

// ----------------------------------------------------------------------------
// 5. gRPC Client Unary & Streaming RPC Exchange
// ----------------------------------------------------------------------------
fn test_grpc_client_rpc_exchange(t: lit::T&) {
    t.run("1. Request Header & Pseudo-Header Construction") { sub =>
        var cfg = grpc::new_call_config("helloworld.Greeter", "SayHello");
        cfg.timeout_ms = 5000;

        var h2_headers = http::HeaderMap { .. };
        grpc::build_request_headers(cfg, "grpc.example.com", "https", h2_headers);

        sub.assert_bytes_eq(http::get_header(h2_headers, ":method"), "POST", ":method is POST");
        sub.assert_bytes_eq(http::get_header(h2_headers, ":scheme"), "https", ":scheme is https");
        sub.assert_bytes_eq(http::get_header(h2_headers, ":path"), "/helloworld.Greeter/SayHello", ":path matches service/method");
        sub.assert_bytes_eq(http::get_header(h2_headers, ":authority"), "grpc.example.com", ":authority matches host");
        sub.assert_bytes_eq(http::get_header(h2_headers, "content-type"), "application/grpc+proto", "content-type application/grpc+proto");
        sub.assert_bytes_eq(http::get_header(h2_headers, "te"), "trailers", "te: trailers required by gRPC");
        sub.assert_bytes_eq(http::get_header(h2_headers, "grpc-timeout"), "5S", "grpc-timeout 5S");
    };

    t.run("2. High-Level Mock Client Unary Call") { sub =>
        var client = client::new_client();

        // Register mock route
        var mock = client::MockExchange {
            pattern_url: "https://api.example.com/order.OrderService/CreateOrder",
            method:      "POST",
            status_code: 200,
            ..
        };
        http::append_header(mock.headers, "content-type", "application/grpc+proto");
        http::append_header(mock.headers, "grpc-status", "0");
        http::append_header(mock.headers, "grpc-message", "Order%20Created");

        // Response body with LPM
        grpc::encode_lpm("order_id_998822", mock.body, false);
        client.mock_routes.push(mock);

        var cfg = grpc::new_call_config("order.OrderService", "CreateOrder");
        var resp = grpc::Response { .. };
        let ok_rpc = grpc::unary_call(client, "https://api.example.com", cfg, "order_request_data", resp);

        sub.assert_true(ok_rpc, "Unary RPC succeeded");
        sub.assert_eq(resp.status, grpc::StatusCode.Ok, "Status is OK");
        sub.assert_bytes_eq(resp.message[..], "Order Created", "Message percent-unescaped");
        sub.assert_bytes_eq(resp.payload[..], "order_id_998822", "LPM response body received");
    };

    t.run("3. Response Trailer Status Extraction") { sub =>
        var res = http::Response { .. };
        res.status_code = 200;
        http::set_header(res, "content-type", "application/grpc+proto");
        http::add_trailer(res, rfc::HEADER_GRPC_STATUS, "7");
        http::add_trailer(res, rfc::HEADER_GRPC_MESSAGE, "Not%20Authorized");

        var status_val = http::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(status_val, "7", "Trailer grpc-status is 7");
        var msg_val = http::trailer(res, rfc::HEADER_GRPC_MESSAGE);
        sub.assert_bytes_eq(msg_val, "Not%20Authorized", "Trailer grpc-message is present");

        var decoded_msg: u8[..256] = [];
        grpc::decode_message(msg_val, decoded_msg);
        sub.assert_bytes_eq(decoded_msg[..], "Not Authorized", "Decoded message matches");
    };

    t.run("4. Request Bloom Filter Indexed in build_grpc_http_request") { sub =>
        var cfg = grpc::new_call_config("order.OrderService", "GetOrder");
        cfg.timeout_ms = 2500;
        var meta = grpc::Metadata { .. };
        meta.key.append("x-trace-id");
        meta.value.append("trace-12345");
        cfg.metadata.push(meta);

        var req = http::new_request("POST", "");
        grpc::build_http_request(cfg, "https://api.example.com", "req_bytes", req);

        sub.assert_bytes_eq(req.header("content-type"), rfc::GRPC_CONTENT_TYPE_PROTO, "content-type indexed");
        sub.assert_bytes_eq(req.header("te"), "trailers", "te indexed");
        sub.assert_bytes_eq(req.header(rfc::HEADER_GRPC_TIMEOUT), "2500m", "grpc-timeout indexed");
        sub.assert_bytes_eq(req.header("x-trace-id"), "trace-12345", "custom metadata indexed in bloom filter");
    };

    t.run("5. Streaming RPC Session (write_stream_message & feed_stream_chunk)") { sub =>
        var client_stream = grpc::new_client_stream(1);

        var wire_out: u8[>..] = [];
        grpc::write_stream_message(client_stream, "Streaming Request 1", wire_out);
        grpc::write_stream_message(client_stream, "Streaming Request 2", wire_out);
        sub.assert_eq(wire_out.len, (5 + 19) + (5 + 19), "Two outbound LPMs written");

        // Simulate inbound server response stream
        var inbound_wire: u8[>..] = [];
        grpc::encode_lpm("Server Event 1", inbound_wire, false);
        grpc::encode_lpm("Server Event 2", inbound_wire, false);

        // Feed half of the bytes first
        let half = inbound_wire.len / 2;
        sub.assert_true(grpc::feed_stream_chunk(client_stream, inbound_wire[..half]), "Fed first half");

        var s_msg: u8[..64] = [];
        var s_comp = false;
        sub.assert_true(grpc::read_stream_message(client_stream, s_msg, s_comp), "First complete message read");
        sub.assert_bytes_eq(s_msg[..], "Server Event 1", "Event 1 matches");

        // Feed remaining half
        sub.assert_true(grpc::feed_stream_chunk(client_stream, inbound_wire[half..]), "Fed second half");
        sub.assert_true(grpc::read_stream_message(client_stream, s_msg, s_comp), "Second complete message read");
        sub.assert_bytes_eq(s_msg[..], "Server Event 2", "Event 2 matches");

        sub.assert_false(grpc::read_stream_message(client_stream, s_msg, s_comp), "No more messages");
    };
}

// ----------------------------------------------------------------------------
// 6. Protobuf LEB128 Wire Field Helpers & GrpcStatus
// ----------------------------------------------------------------------------
fn test_protobuf_wire_helpers(t: lit::T&) {
    t.run("1. GrpcStatus Value Constructors (grpc_ok & grpc_error)") { sub =>
        let st_ok = grpc::ok();
        sub.assert_eq(st_ok.code, grpc::StatusCode.Ok, "grpc_ok returns Ok");
        sub.assert_eq(st_ok.message.len, 0, "grpc_ok has empty message");

        let st_err = grpc::error(grpc::StatusCode.InvalidArgument, "missing field");
        sub.assert_eq(st_err.code, grpc::StatusCode.InvalidArgument, "grpc_error sets code");
        sub.assert_bytes_eq(st_err.message[..], "missing field", "grpc_error sets message");
    };

    t.run("2. Multi-Byte LEB128 Varint & >= 128B Bytes Field Roundtrip") { sub =>
        var wire: u8[..512] = [];
        sub.assert_true(grpc::pb_write_varint_field(1, 300, wire), "Write varint field 1 = 300");

        var long_str: u8[..200] = [];
        for i in 160 {
            long_str.push(('A' + ((i % 26) as u8)));
        }
        sub.assert_true(grpc::pb_write_bytes_field(2, long_str[..], wire), "Write 160B bytes field 2");
        sub.assert_true(grpc::pb_write_varint_field(3, 9876543210, wire), "Write varint field 3");

        let v1, ok1 = grpc::pb_read_varint_field(wire[..], 1);
        sub.assert_true(ok1, "Read varint field 1");
        sub.assert_eq(v1, 300, "Field 1 == 300");

        let b2, ok2 = grpc::pb_read_bytes_field(wire[..], 2);
        sub.assert_true(ok2, "Read 160B bytes field 2 (skips field 1)");
        sub.assert_bytes_eq(b2, long_str[..], "160B multi-byte varint length payload matches");

        let v3, ok3 = grpc::pb_read_varint_field(wire[..], 3);
        sub.assert_true(ok3, "Read varint field 3 (skips fields 1 & 2)");
        sub.assert_eq(v3, 9876543210, "Field 3 matches");
    };

    t.run("3. Transactional Cursor Rollback & Capacity Overflow Guards") { sub =>
        let trunc_varint: u8[2] = [0x80, 0x80];
        var pos: i64 = 0;
        let _, ok_v = grpc::pb_read_varint(trunc_varint[..], pos);
        sub.assert_false(ok_v, "Truncated varint rejected");
        sub.assert_eq(pos, 0, "Cursor preserved on error");

        var tiny: u8[..2] = [];
        sub.assert_false(grpc::pb_write_varint_field(1, 300, tiny), "Overflow varint field rejected");
        sub.assert_eq(tiny.len, 0, "Tiny buffer untouched on overflow");
        sub.assert_false(grpc::pb_write_bytes_field(0, "abc", tiny), "Field 0 rejected");
    };
}

// ----------------------------------------------------------------------------
// 7. 32-bit LPM Length Overflows & Flag Invariants
// ----------------------------------------------------------------------------
fn test_grpc_lpm_integer_overflows(t: lit::T&) {
    t.run("GRPC-SEC-01: 32-bit Integer Overflow in decode_grpc_lpm_slice") { sub =>
        // 0xFFFFFFFF (4294967295) length
        let ovf_hdr: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let _, _, _, ok_ovf = grpc::decode_lpm_slice(ovf_hdr[..], 0);
        sub.assert_false(ok_ovf, "overflow length 0xFFFFFFFF must not wrap around or succeed");

        // 0xFFFFFFFB (4294967291) length: 5 + 0xFFFFFFFB would wrap to 0 if evaluated in u32
        let ovf_wrap: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFB];
        let _, _, _, ok_wrap = grpc::decode_lpm_slice(ovf_wrap[..], 0);
        sub.assert_false(ok_wrap, "overflow length 0xFFFFFFFB must not wrap around or succeed");
    };

    t.run("GRPC-SEC-02: 32-bit Integer Overflow in GrpcStreamParser") { sub =>
        var parser = grpc::new_stream_parser();
        let ovf_chunk: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFB];
        let ok_feed = grpc::feed(parser, ovf_chunk[..]);
        sub.assert_true(ok_feed, "feeding 5-byte header succeeds");

        var payload: u8[..64] = [];
        var compressed = false;
        let ok_msg = grpc::next_message(parser, payload, compressed);
        sub.assert_false(ok_msg, "next_message must not return true on wrapped length");
    };

    t.run("GRPC-SEC-03: 32-bit Integer Overflow in decode_grpc_web_frame") { sub =>
        let ovf_web: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        var payload: u8[..64] = [];
        var is_trailers = false;
        var compressed = false;
        let _, ok_web = grpc::decode_web_frame(ovf_web[..], 0, payload, is_trailers, compressed);
        sub.assert_false(ok_web, "decode_grpc_web_frame must reject overflow length 0xFFFFFFFF");
    };

    t.run("GRPC-SEC-04: Reserved Flag Bits Validation") { sub =>
        // Flag 0x02 (reserved, not compressed 0x01)
        let bad_flag: u8[5] = [0x02, 0x00, 0x00, 0x00, 0x00];
        let _, _, _, ok_flag = grpc::decode_lpm_slice(bad_flag[..], 0);
        sub.assert_false(ok_flag, "LPM flag with reserved bits must be rejected");

        // Flag 0xFE (reserved bits set)
        let bad_flag2: u8[5] = [0xFE, 0x00, 0x00, 0x00, 0x00];
        let _, _, _, ok_flag2 = grpc::decode_lpm_slice(bad_flag2[..], 0);
        sub.assert_false(ok_flag2, "LPM flag 0xFE must be rejected");
    };
}

// ----------------------------------------------------------------------------
// 8. gRPC-Web Trailers Status Parsing
// ----------------------------------------------------------------------------
fn test_grpc_web_trailers_parsing(t: lit::T&) {
    t.run("GRPC-SEC-05: Valid gRPC-Web Trailers Parsing") { sub =>
        let trailer_raw = "grpc-status: 0\r\ngrpc-message: OK\r\n";
        var status = grpc::StatusCode.Internal;
        var msg: u8[..256] = [];
        let ok = grpc::parse_web_trailers(trailer_raw, status, msg);
        sub.assert_true(ok, "parsing valid gRPC-Web trailers succeeds");
        sub.assert_eq(status, grpc::StatusCode.Ok, "grpc-status is Ok");
    };

    t.run("GRPC-SEC-06: Error Status and Non-Zero Error Code") { sub =>
        let trailer_raw = "grpc-status: 14\r\ngrpc-message: Service Unavailable\r\n";
        var status = grpc::StatusCode.Ok;
        var msg: u8[..256] = [];
        let ok = grpc::parse_web_trailers(trailer_raw, status, msg);
        sub.assert_true(ok, "parsing status 14 succeeds");
        sub.assert_eq(status, grpc::StatusCode.Unavailable, "status mapped to Unavailable");
    };
}

fn dummy_unary_handler(
    _handler_id: u16,
    _ctx:        grpc::ServerContext&,
    _req:        const u8[:],
    _res:        u8[>..]&,
) -> grpc::Status {
    return grpc::ok();
}

// ----------------------------------------------------------------------------
// 9. Status & Buffer Bounds Regressions
// ----------------------------------------------------------------------------
fn test_grpc_status_regressions(t: lit::T&) {
    t.run("BUG-1: parse_grpc_status_code rejects non-numeric strings") { sub =>
        let code = grpc::parse_status_code("UNAVAILABLE");
        sub.assert_false(code == 0, "non-numeric status string must not parse as OK (0)");
    };

    t.run("BUG-6: build_grpc_status_details rejects negative code") { sub =>
        var dst: u8[64] = [0; 64];
        let n, ok = grpc::build_status_details(-1, "negative status", dst[..]);
        sub.assert_false(ok, "negative code must be safely rejected");
        sub.assert_false(n < 0, "returned written length must be 0");
    };

    t.run("BUG-4: decode_grpc_message bounded buffer safety") { sub =>
        var long_msg:    u8[300]   = ['a'; 300];
        var out_bounded: u8[..256] = [];
        grpc::decode_message(long_msg[..], out_bounded);
        sub.assert_eq(out_bounded.len, 256, "decode_grpc_message must not exceed out.cap (256)");
    };

    t.run("BUG-5: encode_grpc_message bounded buffer safety") { sub =>
        var raw_msg:     u8[500]   = ['%'; 500];
        var out_bounded: u8[..256] = [];
        grpc::encode_message(raw_msg[..], out_bounded, out_bounded.cap);
        sub.assert_true(out_bounded.len <= 256, "encode_grpc_message must not exceed out.cap (256)");
    };

    t.run("Transactional error and capacity overflow hygiene in trailers, Connect, and status details") { sub =>
        // 1. parse_web_trailers invalid input leaves out_status and out_message untouched
        var wt_st = grpc::StatusCode.Unavailable;
        var wt_msg: u8[..32] = "keep";
        sub.assert_false(
            grpc::parse_web_trailers("not-a-trailer\r\n", wt_st, wt_msg),
            "parse_web_trailers rejects missing grpc-status",
        );
        sub.assert_eq(wt_st, grpc::StatusCode.Unavailable, "wt_st remains Unavailable on parse failure");
        sub.assert_bytes_eq(wt_msg[..], "keep", "wt_msg remains untouched on parse failure");

        // 2. parse_web_trailers out_message capacity overflow returns false with untouched outputs
        var wt_st2 = grpc::StatusCode.Unavailable;
        var wt_tiny: u8[..3] = "old";
        sub.assert_false(
            grpc::parse_web_trailers("grpc-status: 0\r\ngrpc-message: toolongmessage\r\n", wt_st2, wt_tiny),
            "parse_web_trailers rejects out_message overflow",
        );
        sub.assert_eq(wt_st2, grpc::StatusCode.Unavailable, "wt_st2 remains Unavailable on overflow");
        sub.assert_bytes_eq(wt_tiny[..], "old", "wt_tiny remains untouched on overflow");

        // 3. parse_connect_end_stream out_message capacity overflow returns false with untouched outputs
        var ce_st = grpc::StatusCode.Unavailable;
        var ce_tiny: u8[..3] = "old";
        var ce_tr = http::HeaderMap { .. };
        let _ = http::append_header(ce_tr, "x-keep", "1");
        let ce_json = "{\"error\":{\"code\":\"internal\",\"message\":\"toolongmessage\"}}";
        sub.assert_false(
            grpc::parse_connect_end_stream(ce_json, ce_st, ce_tiny, ce_tr),
            "parse_connect_end_stream rejects out_message overflow",
        );
        sub.assert_eq(ce_st, grpc::StatusCode.Unavailable, "ce_st remains Unavailable on overflow");
        sub.assert_bytes_eq(ce_tiny[..], "old", "ce_tiny remains untouched on overflow");
        sub.assert_bytes_eq(http::get_header(ce_tr, "x-keep"), "1", "ce_tr remains untouched on overflow");

        // 4. decode_status_details out_msg capacity overflow returns false with untouched outputs
        var status_pb: u8[..64] = [];
        sub.assert_true(grpc::pb_write_varint_field(1, 3, status_pb), "write code");
        sub.assert_true(grpc::pb_write_bytes_field(2, "toolongmessage", status_pb), "write msg");
        var b64_buf: u8[..128] = [];
        core::base64_encode(status_pb[..], b64_buf);

        var ds_st = grpc::StatusCode.Unavailable;
        var ds_tiny:    u8[..3]                = "old";
        var ds_details: grpc::ErrorDetail[..4] = [];
        var kept_detail = grpc::ErrorDetail { .. };
        let _ = kept_detail.type_url.try_set("keep");
        let _ = ds_details.try_push(kept_detail);

        sub.assert_false(
            grpc::decode_status_details(b64_buf[..], grpc::StatusCode.InvalidArgument, ds_st, ds_tiny, ds_details),
            "decode_status_details rejects out_msg overflow on match",
        );
        sub.assert_eq(ds_st, grpc::StatusCode.Unavailable, "ds_st untouched on match overflow");
        sub.assert_bytes_eq(ds_tiny[..], "old", "ds_tiny untouched on match overflow");
        sub.assert_eq(ds_details.len, 1, "ds_details untouched on match overflow");

        sub.assert_false(
            grpc::decode_status_details(b64_buf[..], grpc::StatusCode.NotFound, ds_st, ds_tiny, ds_details),
            "decode_status_details rejects out_msg overflow on mismatch",
        );
        sub.assert_eq(ds_st, grpc::StatusCode.Unavailable, "ds_st untouched on mismatch overflow");
        sub.assert_bytes_eq(ds_tiny[..], "old", "ds_tiny untouched on mismatch overflow");
        sub.assert_eq(ds_details.len, 1, "ds_details untouched on mismatch overflow");
    };
}
// ----------------------------------------------------------------------------
// 10. Server & Client Regressions
// ----------------------------------------------------------------------------
fn test_grpc_server_and_client_regressions(t: lit::T&) {
    t.run("BUG-2: build_grpc_request_headers with max service and method") { sub =>
        var s: u8[128] = ['s'; 128];
        var m: u8[128] = ['m'; 128];
        var cfg = grpc::CallConfig { .. };
        let _ = cfg.service.try_set(s[..]);
        let _ = cfg.method.try_set(m[..]);
        var headers = http::HeaderMap { .. };
        grpc::build_request_headers(cfg, "example.com", "https", headers);
        let path = http::get_header(headers, ":path");
        sub.assert_eq(path.len, 258, "path must not be truncated to 256 bytes");
    };

    t.run("BUG-3: register_method with 64-byte service and 64-byte method") { sub =>
        var d = grpc::new_server_dispatcher();
        var s: u8[64] = ['s'; 64];
        var m: u8[64] = ['m'; 64];
        let ok_reg = grpc::register_unary(d, s[..], m[..], 1);
        sub.assert_true(ok_reg, "register_unary for 64-byte service and method must succeed");

        var path_buf: u8[..160] = [];
        path_buf.push('/');
        path_buf.append(s[..]);
        path_buf.push('/');
        path_buf.append(m[..]);
        let _, ok_found = grpc::find_method(d, path_buf[..]);
        sub.assert_true(ok_found, "registered method must be found by find_method");
    };

    t.run("BUG-7: Unary 0-byte body rejected with InvalidArgument") { sub =>
        var d = grpc::new_server_dispatcher();
        let _ = grpc::register_unary(d, "test.Service", "EmptyUnary", 1);
        var req = http::new_request("POST", "/test.Service/EmptyUnary");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        // 0-byte body (no 5-byte LPM header)
        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(d, req, 1000, res, dummy_unary_handler);
        sub.assert_true(handled, "handled");
        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "3", "0-byte body must return InvalidArgument (3)");
    };

    t.run("BUG-8: Protobuf 64-bit tag narrowing & field 0 rejection") { sub =>
        let hi_varint: u8[7] = [0x88, 0x80, 0x80, 0x80, 0x80, 0x01, 0x2A];
        let _, ok_v1 = grpc::pb_read_varint_field(hi_varint[..], 1);
        sub.assert_false(ok_v1, "64-bit tag overflowing u32 must not wrap to field 1");

        let zero_fnum: u8[4] = [0x00, 0x01, 0x08, 0x2A];
        let _, ok_v0 = grpc::pb_read_varint_field(zero_fnum[..], 1);
        sub.assert_false(ok_v0, "field number 0 must be rejected");
    };

    t.run("BUG-9: gRPC-Web trailer CRLF injection & multi-chunk Base64") { sub =>
        var ctx = grpc::ServerContext { .. };
        sub.assert_false(grpc::add_response_trailer(ctx, "x-inj", "v\r\ngrpc-status: 0"), "CRLF rejected");
        sub.assert_false(grpc::add_response_trailer(ctx, "grpc-status", "0"), "reserved key rejected");

        var f1: u8[>..] = [];
        grpc::encode_lpm("", f1, false);
        var b64_1: u8[>..] = [];
        grpc::encode_web_text(f1[..], b64_1);
        var f2: u8[>..] = [];
        grpc::encode_web_trailers(grpc::StatusCode.Ok, "ok", f2);
        var b64_2: u8[>..] = [];
        grpc::encode_web_text(f2[..], b64_2);
        var cat: u8[>..] = [];
        cat.append(b64_1[..]);
        cat.append(b64_2[..]);
        var dec: u8[>..] = [];
        sub.assert_true(grpc::decode_web_text(cat[..], dec), "multi-chunk Base64 decoded");
    };

    t.run("BUG-10: Timeout >8 digits & 0S deadline & status HTTP fallback") { sub =>
        var to_buf: u8[..32] = [];
        grpc::encode_timeout(100000500, to_buf);
        let _, ok_to = grpc::parse_timeout(to_buf[..]);
        sub.assert_true(ok_to, "encoded timeout must be <= 8 digits and valid");

        var hdrs = http::HeaderMap { .. };
        hdrs.status_code = 503;
        let _ = http::append_header(hdrs, rfc::HEADER_GRPC_STATUS, "0");
        var trs = http::HeaderMap { .. };
        var msg: u8[..256] = [];
        var st = grpc::StatusCode.Ok;
        let _ = grpc::extract_status(hdrs, trs, st, msg);
        sub.assert_eq(st, grpc::StatusCode.Unavailable, "HTTP 503 overrides grpc-status: 0");
    };
}

// Dummy handler router for test suites
fn test_unary_handler(
    handler_id:  u16,
    ctx:         grpc::ServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> grpc::Status {
    if handler_id == 1 {
        // Greeter.SayHello
        let auth = grpc::get_metadata(ctx, "authorization");
        if auth == "Bearer invalid-token" {
            return grpc::error(grpc::StatusCode.Unauthenticated, "Invalid authorization token");
        }

        grpc::add_response_metadata(ctx, "x-server-version", "wing-grpc-v2");

        res_payload.append("Hello, ");
        res_payload.append(req_payload);
        res_payload.push('!');
        return grpc::ok();
    }
    if handler_id == 99 {
        // Custom error handler
        return grpc::error(grpc::StatusCode.PermissionDenied, "Access forbidden by security policy");
    }
    return grpc::error(grpc::StatusCode.Unimplemented, "Handler not found");
}

// ----------------------------------------------------------------------------
// 11. Unary RPC over HTTP/2
// ----------------------------------------------------------------------------
fn test_grpc_server_unary_http2(t: lit::T&) {
    var dispatcher = grpc::new_server_dispatcher();
    grpc::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);

    t.run("Successful Unary RPC over HTTP/2") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");

        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        http::set_header(req, "authorization", "Bearer valid-token");

        // Body: 5-byte LPM with payload "Alice"
        grpc::encode_lpm("Alice", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);

        sub.assert_true(handled, "Request handled by gRPC dispatcher");
        sub.assert_eq(res.status_code, 200, "HTTP status 200");

        // Validate response headers
        let res_ct = http::header(res, "content-type");
        sub.assert_bytes_eq(res_ct, rfc::GRPC_CONTENT_TYPE_PROTO, "Response content-type is application/grpc");

        let srv_ver = http::header(res, "x-server-version");
        sub.assert_bytes_eq(srv_ver, "wing-grpc-v2", "Custom response metadata header propagated");

        // Validate response body LPM
        var decoded_msg: u8[>..] = [];
        var is_comp = false;
        let consumed, ok_lpm = grpc::decode_lpm(res.body[..], 0, decoded_msg, is_comp);
        sub.assert_true(ok_lpm, "Response body contains valid LPM frame");
        sub.assert_bytes_eq(decoded_msg[..], "Hello, Alice!", "Payload matches greeting");
        sub.assert_false(is_comp, "Uncompressed payload");

        // Validate response trailers
        let grpc_st = http::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(grpc_st, "0", "grpc-status is 0 (OK)");

        // Client-side verification: feed headers + trailers + body into parse_grpc_unary_response
        var hmap = http::HeaderMap { .. };
        http::append_header(hmap, "content-type", res_ct);
        var tmap = http::HeaderMap { .. };
        http::append_header(tmap, rfc::HEADER_GRPC_STATUS, grpc_st);

        var client_resp = grpc::Response { .. };
        let ok_client = grpc::parse_unary_response(hmap, tmap, res.body[..], false, client_resp);
        sub.assert_true(ok_client, "Client parser parsed response");
        sub.assert_eq(client_resp.status, grpc::StatusCode.Ok, "Client status Ok");
        sub.assert_bytes_eq(client_resp.payload[..], "Hello, Alice!", "Client decoded payload");
    };

    t.run("Unary RPC Authentication Failure (Unauthenticated)") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");

        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        http::set_header(req, "authorization", "Bearer invalid-token");

        grpc::encode_lpm("Bob", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);

        sub.assert_true(handled, "Dispatched");
        sub.assert_eq(res.status_code, 200, "HTTP status 200 for gRPC errors");

        // Pure error without payload: must be Trailers-Only in headers!
        sub.assert_eq(res.body.len, 0, "Trailers-Only response has empty body");
        let st_hdr = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st_hdr, "16", "grpc-status 16 (Unauthenticated) in headers");

        let msg_hdr = http::header(res, rfc::HEADER_GRPC_MESSAGE);
        var decoded_msg: u8[..256] = [];
        grpc::decode_message(msg_hdr, decoded_msg);
        sub.assert_bytes_eq(decoded_msg[..], "Invalid authorization token", "Error message preserved");
    };
}

// ----------------------------------------------------------------------------
// 12. Unary RPC over gRPC-Web (Binary & Base64 Text)
// ----------------------------------------------------------------------------
fn test_grpc_server_unary_web(t: lit::T&) {
    var dispatcher = grpc::new_server_dispatcher();
    grpc::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);

    t.run("Binary gRPC-Web (application/grpc-web)") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_WEB_CONTENT_TYPE_PROTO);

        grpc::encode_lpm("WebUser", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Dispatched web request");

        let res_ct = http::header(res, "content-type");
        sub.assert_bytes_eq(res_ct, rfc::GRPC_WEB_CONTENT_TYPE_PROTO, "Response content-type is grpc-web");

        // Verify with client-side gRPC-Web parser
        var hmap = http::HeaderMap { .. };
        http::append_header(hmap, "content-type", res_ct);
        var tmap = http::HeaderMap { .. };

        var client_resp = grpc::Response { .. };
        let ok_parse = grpc::parse_unary_response(hmap, tmap, res.body[..], true, client_resp);
        sub.assert_true(ok_parse, "gRPC-Web response parsed cleanly");
        sub.assert_eq(client_resp.status, grpc::StatusCode.Ok, "Status Ok");
        sub.assert_bytes_eq(client_resp.payload[..], "Hello, WebUser!", "Decoded payload matches");
    };

    t.run("Base64 Text gRPC-Web (application/grpc-web-text)") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_WEB_TEXT_CONTENT_TYPE);

        // Encode LPM into Base64
        var raw_lpm: u8[>..] = [];
        grpc::encode_lpm("TextUser", raw_lpm, false);
        grpc::encode_web_text(raw_lpm[..], req.body);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Dispatched text web request");

        let res_ct = http::header(res, "content-type");
        sub.assert_bytes_eq(res_ct, rfc::GRPC_WEB_TEXT_CONTENT_TYPE, "Response content-type is grpc-web-text");

        // Parse with client gRPC-Web parser
        var hmap = http::HeaderMap { .. };
        http::append_header(hmap, "content-type", res_ct);
        var tmap = http::HeaderMap { .. };

        var client_resp = grpc::Response { .. };
        let ok_parse = grpc::parse_unary_response(hmap, tmap, res.body[..], true, client_resp);
        sub.assert_true(ok_parse, "Text gRPC-Web parsed cleanly");
        sub.assert_eq(client_resp.status, grpc::StatusCode.Ok, "Status Ok");
        sub.assert_bytes_eq(client_resp.payload[..], "Hello, TextUser!", "Decoded payload matches");
    };
}

// ----------------------------------------------------------------------------
// 13. Server-Streaming RPC Dispatch
// ----------------------------------------------------------------------------
fn test_server_streaming_handler(
    handler_id:  u16,
    ctx:         grpc::ServerContext&,
    req_payload: const u8[:],
    writer:      grpc::ServerStreamWriter&,
) -> grpc::Status {
    let _ = ctx;
    let _ = req_payload;
    if handler_id == 2 {
        // Stream 3 events
        grpc::write_stream_message(writer, "Event 1: Connected", false);
        grpc::write_stream_message(writer, "Event 2: Processing", false);
        grpc::write_stream_message(writer, "Event 3: Complete", false);
        return grpc::ok();
    }
    return grpc::error(grpc::StatusCode.Unimplemented, "Handler not found");
}

fn test_grpc_server_streaming(t: lit::T&) {
    var dispatcher = grpc::new_server_dispatcher();
    grpc::register_server_streaming(dispatcher, "event.FeedService", "Subscribe", 2);

    t.run("Server-Streaming produces sequential LPM stream") { sub =>
        var req = http::new_request("POST", "/event.FeedService/Subscribe");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        grpc::encode_lpm("channel_general", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_server_streaming(dispatcher, req, 1000000000, res, test_server_streaming_handler);
        sub.assert_true(handled, "Server streaming dispatched");
        sub.assert_eq(res.status_code, 200, "HTTP 200");

        // Verify sequential messages from stream
        var parser = grpc::new_stream_parser();
        let fed = grpc::feed(parser, res.body[..]);
        sub.assert_true(fed, "Fed response to stream parser");

        var msg1: u8[>..] = [];
        var comp1 = false;
        sub.assert_true(grpc::next_message(parser, msg1, comp1), "Message 1 received");
        sub.assert_bytes_eq(msg1[..], "Event 1: Connected", "Msg 1 content");

        var msg2: u8[>..] = [];
        var comp2 = false;
        sub.assert_true(grpc::next_message(parser, msg2, comp2), "Message 2 received");
        sub.assert_bytes_eq(msg2[..], "Event 2: Processing", "Msg 2 content");

        var msg3: u8[>..] = [];
        var comp3 = false;
        sub.assert_true(grpc::next_message(parser, msg3, comp3), "Message 3 received");
        sub.assert_bytes_eq(msg3[..], "Event 3: Complete", "Msg 3 content");

        var msg4: u8[>..] = [];
        var comp4 = false;
        sub.assert_false(grpc::next_message(parser, msg4, comp4), "No more messages");

        // Verify final status in trailers
        let st = http::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "Final stream trailer is 0 (OK)");
    };
}

// ----------------------------------------------------------------------------
// 14. Client-Streaming RPC Dispatch
// ----------------------------------------------------------------------------
fn test_client_streaming_handler(
    handler_id:  u16,
    ctx:         grpc::ServerContext&,
    reader:      const grpc::ClientStreamReader&,
    res_payload: u8[>..]&,
) -> grpc::Status {
    let _ = ctx;
    if handler_id == 3 {
        let count = reader.spans.len;
        res_payload.append("Received ");
        format(res_payload, count);
        res_payload.append(" items");
        return grpc::ok();
    }
    return grpc::error(grpc::StatusCode.Unimplemented, "Handler not found");
}

fn test_grpc_client_streaming(t: lit::T&) {
    var dispatcher = grpc::new_server_dispatcher();
    grpc::register_client_streaming(dispatcher, "metric.Collector", "UploadBatch", 3);

    t.run("Client-Streaming collects multiple LPM frames") { sub =>
        var req = http::new_request("POST", "/metric.Collector/UploadBatch");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        // Pack 4 messages into request body
        grpc::encode_lpm("item_1", req.body, false);
        grpc::encode_lpm("item_2", req.body, false);
        grpc::encode_lpm("item_3", req.body, false);
        grpc::encode_lpm("item_4", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_client_streaming(dispatcher, req, 1000000000, res, test_client_streaming_handler);
        sub.assert_true(handled, "Client streaming dispatched");

        var decoded: u8[>..] = [];
        var comp = false;
        let _, ok_dec = grpc::decode_lpm(res.body[..], 0, decoded, comp);
        sub.assert_true(ok_dec, "Summary LPM decoded");
        sub.assert_bytes_eq(decoded[..], "Received 4 items", "Summary response payload");

        let st = http::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "grpc-status is OK");
    };
}

// ----------------------------------------------------------------------------
// 15. Error Handling & RFC Protocol Invariants
// ----------------------------------------------------------------------------
fn test_grpc_server_rfc_invariants(t: lit::T&) {
    var dispatcher = grpc::new_server_dispatcher(64); // Max message size = 64 bytes
    grpc::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);
    grpc::register_unary(dispatcher, "secure.Vault", "Access", 99);

    t.run("Unregistered Service or Method returns Unimplemented (12)") { sub =>
        var req = http::new_request("POST", "/unknown.Service/UnknownMethod");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        grpc::encode_lpm("test", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");
        sub.assert_eq(res.status_code, 200, "HTTP status 200");
        sub.assert_eq(res.body.len, 0, "Trailers-Only empty body");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "12", "grpc-status 12 (UNIMPLEMENTED)");

        let msg = http::header(res, rfc::HEADER_GRPC_MESSAGE);
        sub.assert_contains(msg, "Method not found", "Message contains method not found");
    };

    t.run("Malformed URI path returns Unimplemented (12)") { sub =>
        var req = http::new_request("POST", "/single_slash_path");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "12", "grpc-status 12 (UNIMPLEMENTED)");
    };

    t.run("Non-POST HTTP method rejected with Internal (13)") { sub =>
        var req = http::new_request("GET", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "13", "grpc-status 13 (INTERNAL)");
    };

    t.run("Non-gRPC Request ignored (returns false)") { sub =>
        var req = http::new_request("POST", "/api/v1/users");
        http::set_header(req, "content-type", "application/json");

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_false(handled, "Non-gRPC request ignored by gRPC dispatcher");
    };

    t.run("Message Size Exceeds Limit returns ResourceExhausted (8)") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        // 100-byte message when limit is 64
        let big_msg = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        grpc::encode_lpm(big_msg, req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "8", "grpc-status 8 (RESOURCE_EXHAUSTED)");
    };

    t.run("Expired Timeout returns DeadlineExceeded (4)") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        http::set_header(req, rfc::HEADER_GRPC_TIMEOUT, "50m"); // 50 milliseconds

        grpc::encode_lpm("LateUser", req.body, false);

        var res = http::Response { .. };
        // Base time: 1000000000 (1.0s), Timeout 50ms -> Deadline is 1.05s (1050000000). Current time is 1.1s (1100000000).
        let handled = grpc::dispatch_unary(dispatcher, req, 1100000000, res, 1000000000, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "4", "grpc-status 4 (DEADLINE_EXCEEDED)");
    };

    t.run("Custom Handler Error returns PermissionDenied (7)") { sub =>
        var req = http::new_request("POST", "/secure.Vault/Access");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        grpc::encode_lpm("vault_secret_request", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "7", "grpc-status 7 (PERMISSION_DENIED)");

        let msg = http::header(res, rfc::HEADER_GRPC_MESSAGE);
        var decoded_msg: u8[..256] = [];
        grpc::decode_message(msg, decoded_msg);
        sub.assert_bytes_eq(decoded_msg[..], "Access forbidden by security policy", "Error message decoded");
    };

    t.run("Huge Timeout 99999999H does not overflow u64 deadline") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        http::set_header(req, rfc::HEADER_GRPC_TIMEOUT, "99999999H");

        grpc::encode_lpm("Alice", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "grpc-status 0 (OK) - deadline was not falsely triggered");
    };

    t.run("Concatenated LPM frames in Unary RPC rejected with InvalidArgument (3)") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        // Two concatenated LPM messages in unary request
        grpc::encode_lpm("Msg1", req.body, false);
        grpc::encode_lpm("Msg2", req.body, false);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = http::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "3", "grpc-status 3 (INVALID_ARGUMENT)");
    };

    t.run("Bogus Content-Type Prefix rejected by boundary parser") { sub =>
        sub.assert_false(grpc::is_content_type("application/grpc_bogus"), "application/grpc_bogus rejected");
        sub.assert_false(grpc::is_content_type("application/grpc-web-bogus"), "application/grpc-web-bogus rejected");
        sub.assert_true(grpc::is_content_type("application/grpc"), "application/grpc accepted");
        sub.assert_true(grpc::is_content_type("application/grpc+proto"), "application/grpc+proto accepted");
        sub.assert_true(grpc::is_content_type("application/grpc-web+proto"), "application/grpc-web+proto accepted");
        sub.assert_true(grpc::is_content_type("application/grpc-web-text+proto"), "application/grpc-web-text+proto accepted");
    };

    t.run("Gzip Compressed Unary & Client-Streaming Requests Accepted") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        http::set_header(req, rfc::HEADER_GRPC_ENCODING, "gzip");

        grpc::encode_lpm("GzipUser", req.body, true);

        var res = http::Response { .. };
        let handled = grpc::dispatch_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Compressed unary request handled");

        let st = http::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "grpc-status 0 (OK)");

        var decoded_msg: u8[>..] = [];
        var is_comp = false;
        let _, ok_lpm = grpc::decode_lpm(res.body[..], 0, decoded_msg, is_comp);
        sub.assert_true(ok_lpm, "Decoded response LPM");
        sub.assert_bytes_eq(decoded_msg[..], "Hello, GzipUser!", "Decompressed request payload processed by handler");
    };
}

struct TestGrpcStage {
    call_count: u64 = 0,
}

fn grpc::on_unary(
    stage:       TestGrpcStage&,
    handler_id:  u16,
    ctx:         grpc::ServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> grpc::Status {
    let _ = ctx;
    stage.call_count += 1;
    if handler_id == 1 {
        res_payload.append("Stage: ");
        res_payload.append(req_payload);
        return grpc::ok();
    }
    return grpc::error(grpc::StatusCode.Unimplemented, "Unknown stage handler");
}

// ----------------------------------------------------------------------------
// 16. Staged Unary Dispatch
// ----------------------------------------------------------------------------
fn test_grpc_unary_stage_dispatch(t: lit::T&) {
    var dispatcher = grpc::new_server_dispatcher();
    grpc::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);

    t.run("Staged Unary Dispatch invokes custom stage and NoOpStage fallback") { sub =>
        var req = http::new_request("POST", "/helloworld.Greeter/SayHello");
        http::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        grpc::encode_lpm("StageUser", req.body, false);

        var stage = TestGrpcStage { .. };
        var res = http::Response { .. };
        let handled = grpc::dispatch_unary_stage(dispatcher, stage, req, 1000000000, res);
        sub.assert_true(handled, "Handled by stage dispatcher");
        sub.assert_eq(stage.call_count, 1, "Stage call_count incremented");

        var decoded_msg: u8[>..] = [];
        var is_comp = false;
        let _, ok_lpm = grpc::decode_lpm(res.body[..], 0, decoded_msg, is_comp);
        sub.assert_true(ok_lpm, "Decoded stage response LPM");
        sub.assert_bytes_eq(decoded_msg[..], "Stage: StageUser", "Stage response payload matches");

        var noop_stage = wire::NoOpStage {};
        var noop_res = http::Response { .. };
        let noop_handled = grpc::dispatch_unary_stage(dispatcher, noop_stage, req, 1000000000, noop_res);
        sub.assert_true(noop_handled, "Handled by NoOpStage fallback");
        let noop_st = http::header(noop_res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(noop_st, "12", "NoOpStage returns UNIMPLEMENTED (12)");
    };
}

// ----------------------------------------------------------------------------
// 17. Go #21096 & RFC 9110 §7.6.1 / RFC 9113: Forwarding 'TE: trailers' for gRPC
// ----------------------------------------------------------------------------
fn test_grpc_te_trailers_preserved(t: lit::T&) {
    t.run("TE: trailers header must NOT be stripped by strip_hop_by_hop_headers") { sub =>
        var src = http::HeaderMap { .. };
        http::append_header(src, "TE", "trailers");
        http::append_header(src, "Connection", "keep-alive");
        http::append_header(src, "X-Custom", "preserve-me");

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_true(http::has_header(dst, "TE"), "TE: trailers must be preserved across proxies for gRPC (Go #21096)");
        let te_val = http::get_header(dst, "TE");
        sub.assert_bytes_eq(te_val, "trailers", "TE value must remain 'trailers'");
        sub.assert_false(http::has_header(dst, "Connection"), "Connection header must be stripped");
        sub.assert_true(http::has_header(dst, "X-Custom"), "Regular headers must be retained");
    };

    t.run("TE with non-trailers (e.g. TE: gzip, deflate) must be stripped") { sub =>
        var src = http::HeaderMap { .. };
        http::append_header(src, "TE", "gzip, deflate");
        http::append_header(src, "X-Custom", "keep");

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(http::has_header(dst, "TE"), "TE without 'trailers' must be stripped as hop-by-hop");
    };
}

// ----------------------------------------------------------------------------
// 18. gRPC Stream & Status Codecs (grpc/*)
// ----------------------------------------------------------------------------
fn test_grpc_stream_truncation_and_status(t: lit::T&) {
    t.run("parse_client_stream rejects > 32 messages rather than silently dropping 33rd") { sub =>
        var body: u8[>..] = [];
        for i in 33 {
            var msg_buf: u8[..32] = [];
            msg_buf.append("msg");
            format(msg_buf, i);
            grpc::encode_lpm(msg_buf[..], body, false);
        }

        var reader = grpc::ClientStreamReader { .. };
        let ok = grpc::parse_client_stream(body[..], false, reader);
        sub.assert_false(ok, "parse_client_stream with > 32 messages MUST return false to prevent message loss");
    };

    t.run("extract_grpc_status with non-numeric grpc-status sets Unknown") { sub =>
        var hdrs = http::HeaderMap { .. };
        var trls = http::HeaderMap { .. };
        http::append_header(trls, "grpc-status", "invalid-code");

        var status = grpc::StatusCode.Ok;
        var msg: u8[..256] = [];
        grpc::extract_status(hdrs, trls, status, msg);
        sub.assert_true(status == grpc::StatusCode.Unknown, "Non-numeric grpc-status MUST map to GrpcStatusCode.Unknown");
    };

    t.run("parse_grpc_unary_response with truncated 3-byte body returns false") { sub =>
        var hdrs = http::HeaderMap { .. };
        var trls = http::HeaderMap { .. };
        let trunc_body: u8[3] = [0x00, 0x00, 0x05]; // Needs 5 bytes LPM header

        var resp = grpc::Response { .. };
        let ok = grpc::parse_unary_response(hdrs, trls, trunc_body[..], false, resp);
        sub.assert_false(ok, "Truncated gRPC body < 5 bytes MUST return false");
    };
}

fn main() {
    var runner = lit::new_runner("gRPC over HTTP/2, HTTP/3 & gRPC-Web Test Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. gRPC LPM Binary Framing & Codec", test_grpc_lpm_framing);
    lit::run_case(runner, "2. gRPC Incremental Streaming Stream Parser", test_grpc_streaming_parser);
    lit::run_case(runner, "3. gRPC Status Codes, Timeout & Percent-Encoded Messages", test_grpc_status_and_metadata);
    lit::run_case(runner, "4. gRPC-Web Binary & Base64 Text Framing", test_grpc_web_framing);
    lit::run_case(runner, "5. gRPC Client Unary & Streaming RPC Exchange", test_grpc_client_rpc_exchange);
    lit::run_case(runner, "6. Protobuf LEB128 Wire Field Helpers & GrpcStatus", test_protobuf_wire_helpers);
    lit::run_case(runner, "7. 32-bit LPM Length Overflows & Flag Invariants", test_grpc_lpm_integer_overflows);
    lit::run_case(runner, "8. gRPC-Web Trailers Status Parsing", test_grpc_web_trailers_parsing);
    lit::run_case(runner, "9. Status & Buffer Bounds Regressions", test_grpc_status_regressions);
    lit::run_case(runner, "10. Server & Client Regressions", test_grpc_server_and_client_regressions);
    lit::run_case(runner, "11. Unary RPC over HTTP/2", test_grpc_server_unary_http2);
    lit::run_case(runner, "12. Unary RPC over gRPC-Web (Binary & Base64 Text)", test_grpc_server_unary_web);
    lit::run_case(runner, "13. Server-Streaming RPC Dispatch", test_grpc_server_streaming);
    lit::run_case(runner, "14. Client-Streaming RPC Dispatch", test_grpc_client_streaming);
    lit::run_case(runner, "15. Error Handling & RFC Invariants", test_grpc_server_rfc_invariants);
    lit::run_case(runner, "16. Staged Unary Dispatch", test_grpc_unary_stage_dispatch);
    lit::run_case(runner, "17. Go #21096 & RFC 9110 §7.6.1: Forwarding TE: trailers for gRPC", test_grpc_te_trailers_preserved);
    lit::run_case(runner, "18. gRPC stream & status codecs (grpc/*)", test_grpc_stream_truncation_and_status);

    let ok = lit::finish(runner);
    assert(ok);
}
