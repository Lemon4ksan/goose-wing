// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/grpc_server_test.goose
// Verification suite for gRPC Server Dispatcher over HTTP/2, gRPC-Web (binary and text),
// Unary RPCs, Server-Streaming, Client-Streaming, and RFC Error Invariants.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// Dummy handler router for test suites
fn test_unary_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
    out_status:  wing::GrpcStatusCode&,
    out_message: u8[..256]&,
) {
    if handler_id == 1 {
        // Greeter.SayHello
        let auth = wing::get_metadata(ctx, "authorization");
        if auth == "Bearer invalid-token" {
            out_status = wing::GrpcStatusCode.Unauthenticated;
            out_message.append("Invalid authorization token");
            return;
        }

        wing::add_response_metadata(ctx, "x-server-version", "wing-grpc-v2");

        res_payload.append("Hello, ");
        res_payload.append(req_payload);
        res_payload.push('!');
        out_status = wing::GrpcStatusCode.Ok;
    } else if handler_id == 99 {
        // Custom error handler
        out_status = wing::GrpcStatusCode.PermissionDenied;
        out_message.append("Access forbidden by security policy");
    }
}

// ----------------------------------------------------------------------------
// 1. Unary RPC over HTTP/2
// ----------------------------------------------------------------------------
fn test_grpc_server_unary_http2(t: lit::T&) {
    var dispatcher = wing::new_grpc_server_dispatcher();
    wing::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);

    t.run("Successful Unary RPC over HTTP/2") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");

        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var auth = wing::HeaderItem { .. };
        auth.name.append("authorization");
        auth.value.append("Bearer valid-token");
        req.headers.push(auth);

        // Body: 5-byte LPM with payload "Alice"
        wing::encode_grpc_lpm("Alice", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);

        sub.assert_true(handled, "Request handled by gRPC dispatcher");
        sub.assert_eq(res.status_code, 200, "HTTP status 200");

        // Validate response headers
        let res_ct = wing::header(res, "content-type");
        sub.assert_bytes_eq(res_ct, rfc::GRPC_CONTENT_TYPE_PROTO, "Response content-type is application/grpc");

        let srv_ver = wing::header(res, "x-server-version");
        sub.assert_bytes_eq(srv_ver, "wing-grpc-v2", "Custom response metadata header propagated");

        // Validate response body LPM
        var decoded_msg: u8[>..] = [];
        var is_comp = false;
        let ok_lpm, consumed = wing::decode_grpc_lpm(res.body[..], 0, decoded_msg, is_comp);
        sub.assert_true(ok_lpm, "Response body contains valid LPM frame");
        sub.assert_bytes_eq(decoded_msg[..], "Hello, Alice!", "Payload matches greeting");
        sub.assert_false(is_comp, "Uncompressed payload");

        // Validate response trailers
        let grpc_st = wing::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(grpc_st, "0", "grpc-status is 0 (OK)");

        // Client-side verification: feed headers + trailers + body into parse_grpc_unary_response
        var hmap = wing::HeaderMap { .. };
        wing::append_header(hmap, "content-type", res_ct);
        var tmap = wing::HeaderMap { .. };
        wing::append_header(tmap, rfc::HEADER_GRPC_STATUS, grpc_st);

        var client_resp = wing::GrpcResponse { .. };
        let ok_client = wing::parse_grpc_unary_response(hmap, tmap, res.body[..], false, client_resp);
        sub.assert_true(ok_client, "Client parser parsed response");
        sub.assert_eq(client_resp.status, wing::GrpcStatusCode.Ok, "Client status Ok");
        sub.assert_bytes_eq(client_resp.payload[..], "Hello, Alice!", "Client decoded payload");
    };

    t.run("Unary RPC Authentication Failure (Unauthenticated)") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");

        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var auth = wing::HeaderItem { .. };
        auth.name.append("authorization");
        auth.value.append("Bearer invalid-token");
        req.headers.push(auth);

        wing::encode_grpc_lpm("Bob", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);

        sub.assert_true(handled, "Dispatched");
        sub.assert_eq(res.status_code, 200, "HTTP status 200 for gRPC errors");

        // Pure error without payload: must be Trailers-Only in headers!
        sub.assert_eq(res.body.len, 0, "Trailers-Only response has empty body");
        let st_hdr = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st_hdr, "16", "grpc-status 16 (Unauthenticated) in headers");

        let msg_hdr = wing::header(res, rfc::HEADER_GRPC_MESSAGE);
        var decoded_msg: u8[..256] = [];
        wing::decode_grpc_message(msg_hdr, decoded_msg);
        sub.assert_bytes_eq(decoded_msg[..], "Invalid authorization token", "Error message preserved");
    };
}

// ----------------------------------------------------------------------------
// 2. Unary RPC over gRPC-Web (Binary & Base64 Text)
// ----------------------------------------------------------------------------
fn test_grpc_server_unary_web(t: lit::T&) {
    var dispatcher = wing::new_grpc_server_dispatcher();
    wing::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);

    t.run("Binary gRPC-Web (application/grpc-web)") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_WEB_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        wing::encode_grpc_lpm("WebUser", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Dispatched web request");

        let res_ct = wing::header(res, "content-type");
        sub.assert_bytes_eq(res_ct, rfc::GRPC_WEB_CONTENT_TYPE_PROTO, "Response content-type is grpc-web");

        // Verify with client-side gRPC-Web parser
        var hmap = wing::HeaderMap { .. };
        wing::append_header(hmap, "content-type", res_ct);
        var tmap = wing::HeaderMap { .. };

        var client_resp = wing::GrpcResponse { .. };
        let ok_parse = wing::parse_grpc_unary_response(hmap, tmap, res.body[..], true, client_resp);
        sub.assert_true(ok_parse, "gRPC-Web response parsed cleanly");
        sub.assert_eq(client_resp.status, wing::GrpcStatusCode.Ok, "Status Ok");
        sub.assert_bytes_eq(client_resp.payload[..], "Hello, WebUser!", "Decoded payload matches");
    };

    t.run("Base64 Text gRPC-Web (application/grpc-web-text)") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
        req.headers.push(ct);

        // Encode LPM into Base64
        var raw_lpm: u8[>..] = [];
        wing::encode_grpc_lpm("TextUser", raw_lpm, false);
        wing::encode_grpc_web_text(raw_lpm[..], req.body);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Dispatched text web request");

        let res_ct = wing::header(res, "content-type");
        sub.assert_bytes_eq(res_ct, rfc::GRPC_WEB_TEXT_CONTENT_TYPE, "Response content-type is grpc-web-text");

        // Parse with client gRPC-Web parser
        var hmap = wing::HeaderMap { .. };
        wing::append_header(hmap, "content-type", res_ct);
        var tmap = wing::HeaderMap { .. };

        var client_resp = wing::GrpcResponse { .. };
        let ok_parse = wing::parse_grpc_unary_response(hmap, tmap, res.body[..], true, client_resp);
        sub.assert_true(ok_parse, "Text gRPC-Web parsed cleanly");
        sub.assert_eq(client_resp.status, wing::GrpcStatusCode.Ok, "Status Ok");
        sub.assert_bytes_eq(client_resp.payload[..], "Hello, TextUser!", "Decoded payload matches");
    };
}

// ----------------------------------------------------------------------------
// 3. Server-Streaming RPC Dispatch
// ----------------------------------------------------------------------------
fn test_server_streaming_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    writer:      wing::GrpcServerStreamWriter&,
    out_status:  wing::GrpcStatusCode&,
    out_message: u8[..256]&,
) {
    if handler_id == 2 {
        // Stream 3 events
        wing::write_stream_message(writer, "Event 1: Connected", false);
        wing::write_stream_message(writer, "Event 2: Processing", false);
        wing::write_stream_message(writer, "Event 3: Complete", false);
        out_status = wing::GrpcStatusCode.Ok;
    }
}

fn test_grpc_server_streaming(t: lit::T&) {
    var dispatcher = wing::new_grpc_server_dispatcher();
    wing::register_server_streaming(dispatcher, "event.FeedService", "Subscribe", 2);

    t.run("Server-Streaming produces sequential LPM stream") { sub =>
        var req = wing::new_request("POST", "/event.FeedService/Subscribe");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        wing::encode_grpc_lpm("channel_general", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_server_streaming(dispatcher, req, 1000000000, res, test_server_streaming_handler);
        sub.assert_true(handled, "Server streaming dispatched");
        sub.assert_eq(res.status_code, 200, "HTTP 200");

        // Verify sequential messages from stream
        var parser = wing::new_grpc_stream_parser();
        let fed = wing::feed(parser, res.body[..]);
        sub.assert_true(fed, "Fed response to stream parser");

        var msg1: u8[>..] = [];
        var comp1 = false;
        sub.assert_true(wing::next_message(parser, msg1, comp1), "Message 1 received");
        sub.assert_bytes_eq(msg1[..], "Event 1: Connected", "Msg 1 content");

        var msg2: u8[>..] = [];
        var comp2 = false;
        sub.assert_true(wing::next_message(parser, msg2, comp2), "Message 2 received");
        sub.assert_bytes_eq(msg2[..], "Event 2: Processing", "Msg 2 content");

        var msg3: u8[>..] = [];
        var comp3 = false;
        sub.assert_true(wing::next_message(parser, msg3, comp3), "Message 3 received");
        sub.assert_bytes_eq(msg3[..], "Event 3: Complete", "Msg 3 content");

        var msg4: u8[>..] = [];
        var comp4 = false;
        sub.assert_false(wing::next_message(parser, msg4, comp4), "No more messages");

        // Verify final status in trailers
        let st = wing::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "Final stream trailer is 0 (OK)");
    };
}

// ----------------------------------------------------------------------------
// 4. Client-Streaming RPC Dispatch
// ----------------------------------------------------------------------------
fn test_client_streaming_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    reader:      const wing::GrpcClientStreamReader&,
    res_payload: u8[>..]&,
    out_status:  wing::GrpcStatusCode&,
    out_message: u8[..256]&,
) {
    if handler_id == 3 {
        let count = reader.spans.len;
        res_payload.append("Received ");
        format(res_payload, count);
        res_payload.append(" items");
        out_status = wing::GrpcStatusCode.Ok;
    }
}

fn test_grpc_client_streaming(t: lit::T&) {
    var dispatcher = wing::new_grpc_server_dispatcher();
    wing::register_client_streaming(dispatcher, "metric.Collector", "UploadBatch", 3);

    t.run("Client-Streaming collects multiple LPM frames") { sub =>
        var req = wing::new_request("POST", "/metric.Collector/UploadBatch");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        // Pack 4 messages into request body
        wing::encode_grpc_lpm("item_1", req.body, false);
        wing::encode_grpc_lpm("item_2", req.body, false);
        wing::encode_grpc_lpm("item_3", req.body, false);
        wing::encode_grpc_lpm("item_4", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_client_streaming(dispatcher, req, 1000000000, res, test_client_streaming_handler);
        sub.assert_true(handled, "Client streaming dispatched");

        var decoded: u8[>..] = [];
        var comp = false;
        let ok_dec, _ = wing::decode_grpc_lpm(res.body[..], 0, decoded, comp);
        sub.assert_true(ok_dec, "Summary LPM decoded");
        sub.assert_bytes_eq(decoded[..], "Received 4 items", "Summary response payload");

        let st = wing::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "grpc-status is OK");
    };
}

// ----------------------------------------------------------------------------
// 5. Error Handling & RFC Protocol Invariants
// ----------------------------------------------------------------------------
fn test_grpc_server_rfc_invariants(t: lit::T&) {
    var dispatcher = wing::new_grpc_server_dispatcher(64); // Max message size = 64 bytes
    wing::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);
    wing::register_unary(dispatcher, "secure.Vault", "Access", 99);

    t.run("Unregistered Service or Method returns Unimplemented (12)") { sub =>
        var req = wing::new_request("POST", "/unknown.Service/UnknownMethod");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);
        wing::encode_grpc_lpm("test", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");
        sub.assert_eq(res.status_code, 200, "HTTP status 200");
        sub.assert_eq(res.body.len, 0, "Trailers-Only empty body");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "12", "grpc-status 12 (UNIMPLEMENTED)");

        let msg = wing::header(res, rfc::HEADER_GRPC_MESSAGE);
        sub.assert_contains(msg, "Method not found", "Message contains method not found");
    };

    t.run("Malformed URI path returns Unimplemented (12)") { sub =>
        var req = wing::new_request("POST", "/single_slash_path");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "12", "grpc-status 12 (UNIMPLEMENTED)");
    };

    t.run("Non-POST HTTP method rejected with Internal (13)") { sub =>
        var req = wing::new_request("GET", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "13", "grpc-status 13 (INTERNAL)");
    };

    t.run("Non-gRPC Request ignored (returns false)") { sub =>
        var req = wing::new_request("POST", "/api/v1/users");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append("application/json");
        req.headers.push(ct);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_false(handled, "Non-gRPC request ignored by gRPC dispatcher");
    };

    t.run("Message Size Exceeds Limit returns ResourceExhausted (8)") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        // 100-byte message when limit is 64
        let big_msg = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        wing::encode_grpc_lpm(big_msg, req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "8", "grpc-status 8 (RESOURCE_EXHAUSTED)");
    };

    t.run("Expired Timeout returns DeadlineExceeded (4)") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var to = wing::HeaderItem { .. };
        to.name.append(rfc::HEADER_GRPC_TIMEOUT);
        to.value.append("50m"); // 50 milliseconds
        req.headers.push(to);

        wing::encode_grpc_lpm("LateUser", req.body, false);

        var res = wing::Response { .. };
        // Base time: 1000000000 (1.0s), Timeout 50ms -> Deadline is 1.05s (1050000000). Current time is 1.1s (1100000000).
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1100000000, res, 1000000000, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "4", "grpc-status 4 (DEADLINE_EXCEEDED)");
    };

    t.run("Custom Handler Error returns PermissionDenied (7)") { sub =>
        var req = wing::new_request("POST", "/secure.Vault/Access");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        wing::encode_grpc_lpm("vault_secret_request", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "7", "grpc-status 7 (PERMISSION_DENIED)");

        let msg = wing::header(res, rfc::HEADER_GRPC_MESSAGE);
        var decoded_msg: u8[..256] = [];
        wing::decode_grpc_message(msg, decoded_msg);
        sub.assert_bytes_eq(decoded_msg[..], "Access forbidden by security policy", "Error message decoded");
    };

    t.run("Huge Timeout 99999999H does not overflow u64 deadline") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var to = wing::HeaderItem { .. };
        to.name.append(rfc::HEADER_GRPC_TIMEOUT);
        to.value.append("99999999H");
        req.headers.push(to);

        wing::encode_grpc_lpm("Alice", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "grpc-status 0 (OK) - deadline was not falsely triggered");
    };

    t.run("Concatenated LPM frames in Unary RPC rejected with InvalidArgument (3)") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        // Two concatenated LPM messages in unary request
        wing::encode_grpc_lpm("Msg1", req.body, false);
        wing::encode_grpc_lpm("Msg2", req.body, false);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Handled");

        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "3", "grpc-status 3 (INVALID_ARGUMENT)");
    };

    t.run("Bogus Content-Type Prefix rejected by boundary parser") { sub =>
        sub.assert_false(wing::is_grpc_content_type("application/grpc_bogus"), "application/grpc_bogus rejected");
        sub.assert_false(wing::is_grpc_content_type("application/grpc-web-bogus"), "application/grpc-web-bogus rejected");
        sub.assert_true(wing::is_grpc_content_type("application/grpc"), "application/grpc accepted");
        sub.assert_true(wing::is_grpc_content_type("application/grpc+proto"), "application/grpc+proto accepted");
        sub.assert_true(wing::is_grpc_content_type("application/grpc-web+proto"), "application/grpc-web+proto accepted");
        sub.assert_true(wing::is_grpc_content_type("application/grpc-web-text+proto"), "application/grpc-web-text+proto accepted");
    };

    t.run("Gzip Compressed Unary & Client-Streaming Requests Accepted") { sub =>
        var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
        var ct = wing::HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(rfc::GRPC_CONTENT_TYPE_PROTO);
        req.headers.push(ct);

        var enc = wing::HeaderItem { .. };
        enc.name.append(rfc::HEADER_GRPC_ENCODING);
        enc.value.append("gzip");
        req.headers.push(enc);

        wing::encode_grpc_lpm("GzipUser", req.body, true);

        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(dispatcher, req, 1000000000, res, test_unary_handler);
        sub.assert_true(handled, "Compressed unary request handled");

        let st = wing::trailer(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "0", "grpc-status 0 (OK)");

        var decoded_msg: u8[>..] = [];
        var is_comp = false;
        let ok_lpm, _ = wing::decode_grpc_lpm(res.body[..], 0, decoded_msg, is_comp);
        sub.assert_true(ok_lpm, "Decoded response LPM");
        sub.assert_bytes_eq(decoded_msg[..], "Hello, GzipUser!", "Decompressed request payload processed by handler");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = lit::new_runner("gRPC Server Dispatcher Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Unary RPC over HTTP/2", test_grpc_server_unary_http2);
    lit::run_case(runner, "2. Unary RPC over gRPC-Web (Binary & Base64 Text)", test_grpc_server_unary_web);
    lit::run_case(runner, "3. Server-Streaming RPC Dispatch", test_grpc_server_streaming);
    lit::run_case(runner, "4. Client-Streaming RPC Dispatch", test_grpc_client_streaming);
    lit::run_case(runner, "5. Error Handling & RFC Invariants", test_grpc_server_rfc_invariants);

    let ok = lit::finish(runner);
    assert(ok);
}
