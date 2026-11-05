// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/grpc_test.goose
// Verification Suite for gRPC over HTTP/2, HTTP/3, and gRPC-Web Protocol Engine.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_grpc_lpm_framing(t: lit::T&) {
    t.run("1. Uncompressed 5-Byte LPM Frame Encoding & Decoding") { sub =>
        let msg = "Hello gRPC Zero-Heap World!";
        var wire: u8[>..] = [];
        wing::encode_grpc_lpm(msg, wire, false);

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
        let ok_dec, consumed = wing::decode_grpc_lpm(wire[..], 0, decoded_payload, is_comp);

        sub.assert_true(ok_dec, "LPM decoded successfully");
        sub.assert_eq(consumed, wire.len as u32, "Consumed full wire slice");
        sub.assert_false(is_comp, "Compression flag correctly reported as false");
        sub.assert_bytes_eq(decoded_payload[..], msg, "Decoded payload matches original message");
    };

    t.run("2. Compressed LPM Framing") { sub =>
        let msg = "Compressed Protobuf Binary Bytes";
        var wire: u8[>..] = [];
        wing::encode_grpc_lpm(msg, wire, true);

        sub.assert_eq(wire[0], rfc::GRPC_FLAG_COMPRESSED, "Flag byte is 0x01 (GRPC_FLAG_COMPRESSED)");

        var decoded: u8[>..] = [];
        var is_comp = false;
        let ok_dec, consumed = wing::decode_grpc_lpm(wire[..], 0, decoded, is_comp);

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
        wing::encode_grpc_lpm("", wire, false);

        sub.assert_eq(wire.len, 5, "Empty message is exactly 5 bytes");
        sub.assert_eq(wire[0], 0, "Flag is 0");
        sub.assert_eq(wire[1], 0, "Len byte 1 is 0");
        sub.assert_eq(wire[2], 0, "Len byte 2 is 0");
        sub.assert_eq(wire[3], 0, "Len byte 3 is 0");
        sub.assert_eq(wire[4], 0, "Len byte 4 is 0");

        var decoded: u8[>..] = [];
        var is_comp = false;
        let ok_dec, consumed = wing::decode_grpc_lpm(wire[..], 0, decoded, is_comp);

        sub.assert_true(ok_dec, "Decoded empty message");
        sub.assert_eq(consumed, 5, "Consumed 5 bytes");
        sub.assert_eq(decoded.len, 0, "Decoded payload is empty");
    };

    t.run("4. Truncated Frame Guards") { sub =>
        let msg = "Test Truncation";
        var wire: u8[>..] = [];
        wing::encode_grpc_lpm(msg, wire, false);

        var decoded: u8[>..] = [];
        var is_comp = false;

        // Truncate header (< 5 bytes)
        let ok_hdr, _ = wing::decode_grpc_lpm(wire[..4], 0, decoded, is_comp);
        sub.assert_false(ok_hdr, "Truncated header rejected");

        // Truncate payload
        let ok_pay, _ = wing::decode_grpc_lpm(wire[..(wire.len - 2)], 0, decoded, is_comp);
        sub.assert_false(ok_pay, "Truncated payload rejected");

        // Reserved flag bits rejected per gRPC Wire Protocol
        var bad_flag_wire: u8[5] = [0x02, 0, 0, 0, 0];
        let ok_bad_flag, _ = wing::decode_grpc_lpm(bad_flag_wire[..], 0, decoded, is_comp);
        sub.assert_false(ok_bad_flag, "Reserved flag bit 0x02 rejected");
    };

    t.run("5. Concatenated Multi-LPM Sequential Extraction") { sub =>
        var stream_bytes: u8[>..] = [];
        wing::encode_grpc_lpm("Message1", stream_bytes, false);
        wing::encode_grpc_lpm("Message2", stream_bytes, true);
        wing::encode_grpc_lpm("Message3", stream_bytes, false);

        var offset: u32 = 0;
        var count = 0;
        var payloads:   u8[..64][..4] = [];
        var comp_flags: bool[..4]     = [];

        while offset < (stream_bytes.len as u32) {
            var msg_buf: u8[..64] = [];
            var comp = false;
            let ok_msg, consumed = wing::decode_grpc_lpm(stream_bytes[..], offset, msg_buf, comp);
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

fn test_grpc_streaming_parser(t: lit::T&) {
    t.run("1. Piecewise Fragmented Ingestion Across DATA Frame Chunks") { sub =>
        var parser = wing::new_grpc_stream_parser();

        let full_msg = "Chunked Streaming gRPC Verification Payload!";
        var wire: u8[>..] = [];
        wing::encode_grpc_lpm(full_msg, wire, false);

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
        var parser = wing::new_grpc_stream_parser();

        var multi: u8[>..] = [];
        wing::encode_grpc_lpm("Alpha", multi, false);
        wing::encode_grpc_lpm("Beta", multi, false);
        wing::encode_grpc_lpm("Gamma", multi, false);

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

fn test_grpc_status_and_metadata(t: lit::T&) {
    t.run("1. Canonical Status Code Mapping (0..16)") { sub =>
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.Ok), 0, "OK code 0");
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.Cancelled), 1, "Cancelled code 1");
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.InvalidArgument), 3, "InvalidArgument code 3");
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.DeadlineExceeded), 4, "DeadlineExceeded code 4");
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.NotFound), 5, "NotFound code 5");
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.PermissionDenied), 7, "PermissionDenied code 7");
        sub.assert_eq(wing::grpc_status_to_code(wing::GrpcStatusCode.Unauthenticated), 16, "Unauthenticated code 16");

        sub.assert_bytes_eq(wing::grpc_status_name(wing::GrpcStatusCode.Ok), "OK", "Name OK");
        sub.assert_bytes_eq(wing::grpc_status_name(wing::GrpcStatusCode.Internal), "INTERNAL", "Name INTERNAL");
        sub.assert_bytes_eq(wing::grpc_status_name(wing::GrpcStatusCode.Unavailable), "UNAVAILABLE", "Name UNAVAILABLE");

        // HTTP status fallbacks per gRPC HTTP/2 Status Mapping
        sub.assert_eq(wing::grpc_status_from_http(200), wing::GrpcStatusCode.Unknown, "HTTP 200 without grpc-status -> Unknown");
        sub.assert_eq(wing::grpc_status_from_http(400), wing::GrpcStatusCode.Internal, "HTTP 400 -> Internal");
        sub.assert_eq(wing::grpc_status_from_http(401), wing::GrpcStatusCode.Unauthenticated, "HTTP 401 -> Unauthenticated");
        sub.assert_eq(wing::grpc_status_from_http(403), wing::GrpcStatusCode.PermissionDenied, "HTTP 403 -> PermissionDenied");
        sub.assert_eq(wing::grpc_status_from_http(404), wing::GrpcStatusCode.Unimplemented, "HTTP 404 -> Unimplemented");
        sub.assert_eq(wing::grpc_status_from_http(429), wing::GrpcStatusCode.ResourceExhausted, "HTTP 429 -> ResourceExhausted");
        sub.assert_eq(wing::grpc_status_from_http(503), wing::GrpcStatusCode.Unavailable, "HTTP 503 -> Unavailable");
        sub.assert_eq(wing::grpc_status_from_http(504), wing::GrpcStatusCode.DeadlineExceeded, "HTTP 504 -> DeadlineExceeded");
    };

    t.run("2. grpc-message Percent-Encoding & Decoding") { sub =>
        let raw = "Record with ID #42 not found: user%account";
        var encoded: u8[>..] = [];
        wing::encode_grpc_message(raw, encoded);

        // '%' and '#' must be percent encoded
        var decoded: u8[>..] = [];
        wing::decode_grpc_message(encoded[..], decoded);
        sub.assert_bytes_eq(decoded[..], raw, "Percent decode restores original error message exactly");

        // Verify non-ASCII characters
        let non_ascii: u8[3] = [0xE2, 0x82, 0xAC]; // Euro symbol in UTF-8
        var enc_na: u8[>..] = [];
        wing::encode_grpc_message(non_ascii[..], enc_na);
        sub.assert_bytes_eq(enc_na[..], "%E2%82%AC", "Non-ASCII encoded as %XX uppercase hex");

        var dec_na: u8[>..] = [];
        wing::decode_grpc_message(enc_na[..], dec_na);
        sub.assert_bytes_eq(dec_na[..], non_ascii[..], "Decoded non-ASCII matches");
    };

    t.run("3. grpc-timeout Formatting & Parsing") { sub =>
        var out_t: u8[..32] = [];

        // Exact seconds
        wing::encode_grpc_timeout(10000, out_t);
        sub.assert_bytes_eq(out_t[..], "10S", "10000ms encoded as 10S");

        // Exact minutes
        out_t.clear();
        wing::encode_grpc_timeout(120000, out_t);
        sub.assert_bytes_eq(out_t[..], "2M", "120000ms encoded as 2M");

        // Exact hours
        out_t.clear();
        wing::encode_grpc_timeout(7200000, out_t);
        sub.assert_bytes_eq(out_t[..], "2H", "7200000ms encoded as 2H");

        // Milliseconds
        out_t.clear();
        wing::encode_grpc_timeout(500, out_t);
        sub.assert_bytes_eq(out_t[..], "500m", "500ms encoded as 500m");

        // Parsing
        let ms_s, ok_s = wing::parse_grpc_timeout("10S");
        sub.assert_true(ok_s, "Parsed 10S");
        sub.assert_eq(ms_s, 10000, "10S is 10000ms");

        let ms_m, ok_m = wing::parse_grpc_timeout("500m");
        sub.assert_true(ok_m, "Parsed 500m");
        sub.assert_eq(ms_m, 500, "500m is 500ms");

        let ms_u, ok_u = wing::parse_grpc_timeout("1000u");
        sub.assert_true(ok_u, "Parsed 1000u");
        sub.assert_eq(ms_u, 1, "1000 microseconds is 1ms");

        let ms_h, ok_h = wing::parse_grpc_timeout("1H");
        sub.assert_true(ok_h, "Parsed 1H");
        sub.assert_eq(ms_h, 3600000, "1H is 3600000ms");
    };

    t.run("4. Status Extraction from Response Headers and Trailers") { sub =>
        var headers = wing::HeaderMap { .. };
        headers.status_code = 200;

        var trailers = wing::HeaderMap { .. };
        wing::append_header(trailers, "grpc-status", "0");
        wing::append_header(trailers, "grpc-message", "OK");

        var status = wing::GrpcStatusCode.Unknown;
        var msg: u8[..256] = [];
        let has_status = wing::extract_grpc_status(headers, trailers, status, msg);

        sub.assert_true(has_status, "Explicit status extracted from trailers");
        sub.assert_eq(status, wing::GrpcStatusCode.Ok, "Status is OK");
        sub.assert_bytes_eq(msg[..], "OK", "Message is OK");

        // Trailers-only response (immediate error in headers)
        var err_headers = wing::HeaderMap { .. };
        err_headers.status_code = 200;
        wing::append_header(err_headers, "grpc-status", "7");
        wing::append_header(err_headers, "grpc-message", "permission%20denied");

        var empty_trailers = wing::HeaderMap { .. };
        let has_err = wing::extract_grpc_status(err_headers, empty_trailers, status, msg);
        sub.assert_true(has_err, "Status extracted from headers in Trailers-Only case");
        sub.assert_eq(status, wing::GrpcStatusCode.PermissionDenied, "Status is PermissionDenied");
        sub.assert_bytes_eq(msg[..], "permission denied", "Message unescaped");
    };
}

fn test_grpc_web_framing(t: lit::T&) {
    t.run("1. Trailers-in-Body Encoding with Flag 0x80") { sub =>
        var web_trailers: u8[>..] = [];
        wing::encode_grpc_web_trailers(wing::GrpcStatusCode.InvalidArgument, "invalid argument provided", web_trailers);

        sub.assert_eq(web_trailers[0], rfc::GRPC_WEB_FLAG_TRAILERS, "Flag has bit 7 set (0x80)");

        var payload: u8[>..] = [];
        var is_trailers = false;
        var is_comp = false;
        let ok_dec, consumed = wing::decode_grpc_web_frame(web_trailers[..], 0, payload, is_trailers, is_comp);

        sub.assert_true(ok_dec, "Frame decoded");
        sub.assert_true(is_trailers, "Frame marked as trailers");
        sub.assert_false(is_comp, "Uncompressed");

        var st = wing::GrpcStatusCode.Ok;
        var msg: u8[..256] = [];
        let parsed = wing::parse_grpc_web_trailers(payload[..], st, msg);
        sub.assert_true(parsed, "Parsed gRPC-Web trailers block");
        sub.assert_eq(st, wing::GrpcStatusCode.InvalidArgument, "Status is InvalidArgument");
        sub.assert_bytes_eq(msg[..], "invalid argument provided", "Message extracted");
    };

    t.run("2. gRPC-Web Binary Response Stream with Data + Trailers") { sub =>
        var stream: u8[>..] = [];

        // Data frame
        let data_msg = "Unary Response Data Payload";
        wing::encode_grpc_lpm(data_msg, stream, false);

        // Trailer frame (flag 0x80)
        wing::encode_grpc_web_trailers(wing::GrpcStatusCode.Ok, "OK", stream);

        var offset: u32 = 0;

        // Frame 1: Data
        var f1_payload: u8[>..] = [];
        var f1_is_trailers = false;
        var f1_comp = false;
        let ok_f1, cons1 = wing::decode_grpc_web_frame(stream[..], offset, f1_payload, f1_is_trailers, f1_comp);
        sub.assert_true(ok_f1, "Decoded f1");
        sub.assert_false(f1_is_trailers, "f1 is data");
        sub.assert_bytes_eq(f1_payload[..], data_msg, "Data payload matches");
        offset += cons1;

        // Frame 2: Trailers
        var f2_payload: u8[>..] = [];
        var f2_is_trailers = false;
        var f2_comp = false;
        let ok_f2, cons2 = wing::decode_grpc_web_frame(stream[..], offset, f2_payload, f2_is_trailers, f2_comp);
        sub.assert_true(ok_f2, "Decoded f2");
        sub.assert_true(f2_is_trailers, "f2 is trailers");

        var st = wing::GrpcStatusCode.Unknown;
        var msg: u8[..256] = [];
        wing::parse_grpc_web_trailers(f2_payload[..], st, msg);
        sub.assert_eq(st, wing::GrpcStatusCode.Ok, "Status OK in trailers");
    };

    t.run("3. gRPC-Web Text Base64 Stream Codec") { sub =>
        var binary_stream: u8[>..] = [];
        wing::encode_grpc_lpm("Base64 Encoded gRPC Message", binary_stream, false);

        var b64_text: u8[>..] = [];
        wing::encode_grpc_web_text(binary_stream[..], b64_text);
        sub.assert_true(b64_text.len > binary_stream.len, "Base64 text produced");

        var restored_bin: u8[>..] = [];
        let ok_dec = wing::decode_grpc_web_text(b64_text[..], restored_bin);
        sub.assert_true(ok_dec, "Decoded base64 text");
        sub.assert_bytes_eq(restored_bin[..], binary_stream[..], "Restored binary bytes match exactly");

        var msg: u8[>..] = [];
        var comp = false;
        let ok_lpm, _ = wing::decode_grpc_lpm(restored_bin[..], 0, msg, comp);
        sub.assert_true(ok_lpm, "LPM extracted from decoded Base64");
        sub.assert_bytes_eq(msg[..], "Base64 Encoded gRPC Message", "Payload correct");
    };
}

fn test_grpc_client_rpc_exchange(t: lit::T&) {
    t.run("1. Request Header & Pseudo-Header Construction") { sub =>
        var cfg = wing::new_grpc_call_config("helloworld.Greeter", "SayHello");
        cfg.timeout_ms = 5000;

        var h2_headers = wing::HeaderMap { .. };
        wing::build_grpc_request_headers(cfg, "grpc.example.com", "https", h2_headers);

        sub.assert_bytes_eq(wing::get_header(h2_headers, ":method"), "POST", ":method is POST");
        sub.assert_bytes_eq(wing::get_header(h2_headers, ":scheme"), "https", ":scheme is https");
        sub.assert_bytes_eq(wing::get_header(h2_headers, ":path"), "/helloworld.Greeter/SayHello", ":path matches service/method");
        sub.assert_bytes_eq(wing::get_header(h2_headers, ":authority"), "grpc.example.com", ":authority matches host");
        sub.assert_bytes_eq(wing::get_header(h2_headers, "content-type"), "application/grpc+proto", "content-type application/grpc+proto");
        sub.assert_bytes_eq(wing::get_header(h2_headers, "te"), "trailers", "te: trailers required by gRPC");
        sub.assert_bytes_eq(wing::get_header(h2_headers, "grpc-timeout"), "5S", "grpc-timeout 5S");
    };

    t.run("2. High-Level Mock Client Unary Call") { sub =>
        var client = wing::new_client();

        // Register mock route
        var mock = wing::MockExchange {
            pattern_url: "https://api.example.com/order.OrderService/CreateOrder",
            method:      "POST",
            status_code: 200,
            ..
        };
        wing::append_header(mock.headers, "content-type", "application/grpc+proto");
        wing::append_header(mock.headers, "grpc-status", "0");
        wing::append_header(mock.headers, "grpc-message", "Order%20Created");

        // Response body with LPM
        wing::encode_grpc_lpm("order_id_998822", mock.body, false);
        client.mock_routes.push(mock);

        var cfg = wing::new_grpc_call_config("order.OrderService", "CreateOrder");
        var resp = wing::GrpcResponse { .. };
        let ok_rpc = wing::grpc_unary_call(client, "https://api.example.com", cfg, "order_request_data", resp);

        sub.assert_true(ok_rpc, "Unary RPC succeeded");
        sub.assert_eq(resp.status, wing::GrpcStatusCode.Ok, "Status is OK");
        sub.assert_bytes_eq(resp.message[..], "Order Created", "Message percent-unescaped");
        sub.assert_bytes_eq(resp.payload[..], "order_id_998822", "LPM response body received");
    };

    t.run("3. Response Trailer Status Extraction") { sub =>
        var res = wing::Response { .. };
        res.status_code = 200;
        wing::set_header(res, "content-type", "application/grpc+proto");
        wing::add_trailer(res, rfc::HEADER_GRPC_STATUS, "7");
        wing::add_trailer(res, rfc::HEADER_GRPC_MESSAGE, "Not%20Authorized");

        var status_val = wing::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(status_val, "7", "Trailer grpc-status is 7");
        var msg_val = wing::trailer(res, rfc::HEADER_GRPC_MESSAGE);
        sub.assert_bytes_eq(msg_val, "Not%20Authorized", "Trailer grpc-message is present");

        var decoded_msg: u8[..256] = [];
        wing::decode_grpc_message(msg_val, decoded_msg);
        sub.assert_bytes_eq(decoded_msg[..], "Not Authorized", "Decoded message matches");
    };

    t.run("4. Request Bloom Filter Indexed in build_grpc_http_request") { sub =>
        var cfg = wing::new_grpc_call_config("order.OrderService", "GetOrder");
        cfg.timeout_ms = 2500;
        var meta = wing::GrpcMetadata { .. };
        meta.key.append("x-trace-id");
        meta.value.append("trace-12345");
        cfg.metadata.push(meta);

        var req = wing::new_request("POST", "");
        wing::build_grpc_http_request(cfg, "https://api.example.com", "req_bytes", req);

        sub.assert_bytes_eq(req.header("content-type"), rfc::GRPC_CONTENT_TYPE_PROTO, "content-type indexed");
        sub.assert_bytes_eq(req.header("te"), "trailers", "te indexed");
        sub.assert_bytes_eq(req.header(rfc::HEADER_GRPC_TIMEOUT), "2500m", "grpc-timeout indexed");
        sub.assert_bytes_eq(req.header("x-trace-id"), "trace-12345", "custom metadata indexed in bloom filter");
    };

    t.run("5. Streaming RPC Session (write_stream_message & feed_stream_chunk)") { sub =>
        var client_stream = wing::new_grpc_client_stream(1);

        var wire_out: u8[>..] = [];
        wing::write_stream_message(client_stream, "Streaming Request 1", wire_out);
        wing::write_stream_message(client_stream, "Streaming Request 2", wire_out);
        sub.assert_eq(wire_out.len, (5 + 19) + (5 + 19), "Two outbound LPMs written");

        // Simulate inbound server response stream
        var inbound_wire: u8[>..] = [];
        wing::encode_grpc_lpm("Server Event 1", inbound_wire, false);
        wing::encode_grpc_lpm("Server Event 2", inbound_wire, false);

        // Feed half of the bytes first
        let half = inbound_wire.len / 2;
        sub.assert_true(wing::feed_stream_chunk(client_stream, inbound_wire[..half]), "Fed first half");

        var s_msg: u8[..64] = [];
        var s_comp = false;
        sub.assert_true(wing::read_stream_message(client_stream, s_msg, s_comp), "First complete message read");
        sub.assert_bytes_eq(s_msg[..], "Server Event 1", "Event 1 matches");

        // Feed remaining half
        sub.assert_true(wing::feed_stream_chunk(client_stream, inbound_wire[half..]), "Fed second half");
        sub.assert_true(wing::read_stream_message(client_stream, s_msg, s_comp), "Second complete message read");
        sub.assert_bytes_eq(s_msg[..], "Server Event 2", "Event 2 matches");

        sub.assert_false(wing::read_stream_message(client_stream, s_msg, s_comp), "No more messages");
    };
}

fn main() {
    var runner = lit::new_runner("gRPC over HTTP/2, HTTP/3 & gRPC-Web Test Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. gRPC LPM Binary Framing & Codec", test_grpc_lpm_framing);
    lit::run_case(runner, "2. gRPC Incremental Streaming Stream Parser", test_grpc_streaming_parser);
    lit::run_case(runner, "3. gRPC Status Codes, Timeout & Percent-Encoded Messages", test_grpc_status_and_metadata);
    lit::run_case(runner, "4. gRPC-Web Binary & Base64 Text Framing", test_grpc_web_framing);
    lit::run_case(runner, "5. gRPC Client Unary & Streaming RPC Exchange", test_grpc_client_rpc_exchange);

    let ok = lit::finish(runner);
    assert(ok);
}
